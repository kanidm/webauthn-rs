//! Helpers for framing U2FHID messages.
//!
//! USB HID has a MTU (maximum transmission unit) of 64 bytes. U2FHID headers
//! are 7 bytes for the first frame of a message, and 5 bytes for every message
//! thereafter.
//!
//! So, we need to be able to fragment our messages before sending them to a
//! token, and then defragment them on the other side.
use crate::error::WebauthnCError;
use crate::usb::{HidReportBytes, HidSendReportBytes};
use std::cmp::min;
use std::iter::Sum;
use std::mem::size_of;
use std::ops::{Add, AddAssign};

/// The maximum data payload for the initial fragment of a message, in bytes.
const INITIAL_FRAGMENT_SIZE: usize = size_of::<HidReportBytes>() - 7;
/// The maximum data payload for the second and subsequent fragments of a
/// message, in bytes.
const FRAGMENT_SIZE: usize = size_of::<HidReportBytes>() - 5;
/// Maximum total size for a U2FHID message after chunking, in bytes.
pub const MAX_SIZE: usize = INITIAL_FRAGMENT_SIZE + (0x80 * FRAGMENT_SIZE);

/// U2F HID request frame type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U2FHIDFrame {
    /// Channel identifier
    pub cid: u32,
    /// Command identifier or sequence number
    pub cmd: u8,
    /// Complete length of the frame.
    pub len: u16,
    /// Data payload, of up to [MAX_SIZE] bytes.
    pub data: Vec<u8>,
}

impl U2FHIDFrame {
    /// Returns `true` if the frame is an initial fragment and
    /// [Self::len] == 0 or [Self::data.len].
    ///
    /// Frames fragmented by [U2FHIDFrameIterator] return `false`.
    ///
    /// Frames that have been _partially_ or _fully_ reassembled by [Add],
    /// [AddAssign] or [Sum] return `true`.
    pub fn complete(&self) -> bool {
        self.cmd & 0x80 > 0 && (self.len == 0 || self.data.len() == usize::from(self.len))
    }
}

const EMPTY_FRAME: U2FHIDFrame = U2FHIDFrame {
    cid: 0,
    cmd: 0,
    len: 0,
    data: vec![],
};

/// Iterator type for fragmenting a long [U2FHIDFrame] into smaller pieces that
/// fit within the USB HID MTU.
pub struct U2FHIDFrameIterator<'a> {
    /// The frame to fragment.
    f: &'a U2FHIDFrame,
    /// The current position within the frame we're up to.
    p: &'a [u8],
    /// The fragment number we're up to.
    i: u8,
    /// If we've done the first iteration.
    s: bool,
}

impl<'a> U2FHIDFrameIterator<'a> {
    /// Creates a new iterator for fragmenting [U2FHIDFrame]
    pub fn new(f: &'a U2FHIDFrame) -> Result<Self, WebauthnCError> {
        if f.data.len() > MAX_SIZE {
            return Err(WebauthnCError::MessageTooLarge);
        }
        Ok(U2FHIDFrameIterator {
            f,
            p: &f.data,
            i: 0,
            s: false,
        })
    }
}

impl Iterator for U2FHIDFrameIterator<'_> {
    type Item = U2FHIDFrame;

    fn next(&mut self) -> Option<Self::Item> {
        let l = self.p.len();
        let (data, p) = self.p.split_at(min(
            l,
            if self.s {
                FRAGMENT_SIZE
            } else {
                INITIAL_FRAGMENT_SIZE
            },
        ));
        self.p = p;

        if !self.s {
            // First round
            self.s = true;
            Some(U2FHIDFrame {
                len: l as u16,
                data: data.to_vec(),
                ..*self.f
            })
        } else if l == 0 {
            // Already consumed iterator.
            None
        } else {
            let i = self.i & 0x7f;
            self.i = i + 1;
            Some(U2FHIDFrame {
                cid: self.f.cid,
                cmd: i,
                len: 0,
                data: data.to_vec(),
            })
        }
    }
}

/// Merges fragmented [U2FHIDFrame]s back together. Assumes the LHS of the
/// operation is the initial fragment.
impl Add for U2FHIDFrame {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        assert_eq!(self.cid, rhs.cid);
        assert_ne!(self.len, 0);

        let mut o: Vec<u8> = vec![0; usize::from(self.len)];
        o[..self.data.len()].copy_from_slice(&self.data);

        let p = INITIAL_FRAGMENT_SIZE + (usize::from(rhs.cmd) * FRAGMENT_SIZE);
        let q = min(p + rhs.data.len(), usize::from(self.len));
        o[p..q].copy_from_slice(&rhs.data[..q - p]);
        U2FHIDFrame { data: o, ..self }
    }
}

/// Merges fragmented [U2FHIDFrame]s back together. Assumes the LHS of the
/// operation is the initial fragment.
impl AddAssign for U2FHIDFrame {
    fn add_assign(&mut self, rhs: U2FHIDFrame) {
        assert_eq!(self.cid, rhs.cid);
        assert_ne!(self.len, 0);

        if self.data.len() != usize::from(self.len) {
            // The `data` buffer in `self` is too short, expand it to its proper
            // size.
            let mut o: Vec<u8> = vec![0; usize::from(self.len)];
            o[..self.data.len()].copy_from_slice(&self.data);
            self.data = o;
        }

        let p = INITIAL_FRAGMENT_SIZE + (usize::from(rhs.cmd) * FRAGMENT_SIZE);
        let q = min(p + rhs.data.len(), usize::from(self.len));
        self.data[p..q].copy_from_slice(&rhs.data[..q - p]);
    }
}

/// Merges fragmented [U2FHIDFrame]s back together. Assumes the first element
/// is the initial fragment. Order of subsequent fragments doesn't matter.
impl<'a> Sum<&'a U2FHIDFrame> for U2FHIDFrame {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        // First frame
        let mut s: Option<&Self> = None;
        let mut o: Vec<u8> = Vec::with_capacity(0);

        for f in iter {
            match &s {
                None => {
                    o = vec![0; usize::from(f.len)];
                    let p = min(f.data.len(), usize::from(f.len));
                    o[..p].copy_from_slice(&f.data[..p]);
                    s = Some(f);
                }

                Some(first) => {
                    assert_eq!(f.cid, first.cid);
                    let p = INITIAL_FRAGMENT_SIZE + (usize::from(f.cmd) * FRAGMENT_SIZE);
                    let q = min(p + f.data.len(), usize::from(first.len));
                    o[p..q].copy_from_slice(&f.data[..q - p]);
                }
            }
        }
        match s {
            Some(first) => U2FHIDFrame { data: o, ..*first },
            None => EMPTY_FRAME,
        }
    }
}

impl From<&U2FHIDFrame> for HidSendReportBytes {
    /// Serialises a [U2FHIDFrame] to bytes to be sent via a USB HID report.
    ///
    /// This does not fragment packets: see [U2FHIDFrameIterator].
    fn from(f: &U2FHIDFrame) -> HidSendReportBytes {
        let mut o: HidSendReportBytes = [0; size_of::<HidSendReportBytes>()];

        // o[0] = 0; (Report ID)
        o[1..5].copy_from_slice(&f.cid.to_be_bytes());
        o[5] = f.cmd;

        if f.cmd & 0x80 > 0 {
            // Initial
            o[6..8].copy_from_slice(&(f.len).to_be_bytes());
            o[8..8 + f.data.len()].copy_from_slice(&f.data);
        } else {
            o[6..6 + f.data.len()].copy_from_slice(&f.data);
        }

        o
    }
}

/// Deserialises bytes from a USB HID report into a [U2FHIDFrame].
impl TryFrom<&HidReportBytes> for U2FHIDFrame {
    type Error = WebauthnCError;

    fn try_from(b: &HidReportBytes) -> Result<Self, Self::Error> {
        let (cid, b) = b.split_at(4);
        let cid = u32::from_be_bytes(
            cid.try_into()
                .map_err(|_| WebauthnCError::MessageTooShort)?,
        );
        let (cmd, b) = (b[0], &b[1..]);
        if cmd & 0x80 > 0 {
            // Initial
            let (len, b) = b.split_at(2);
            let len = u16::from_be_bytes(
                len.try_into()
                    .map_err(|_| WebauthnCError::MessageTooShort)?,
            );
            // Resize the buffer for short messages
            let b = &b[..min(b.len(), usize::from(len))];

            Ok(Self {
                cid,
                cmd,
                len,
                data: b.to_vec(),
            })
        } else {
            // Continuation
            Ok(Self {
                cid,
                cmd,
                len: 0,
                data: b.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WebauthnCError;

    #[test]
    fn fragment_short() {
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 2,
            data: vec![1, 2],
        };

        let fragments: Vec<U2FHIDFrame> = U2FHIDFrameIterator::new(&full).unwrap().collect();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], full);

        let assembled: U2FHIDFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
    }

    #[test]
    fn fragment_long() {
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 255,
            data: (0..255).collect(),
        };
        assert!(full.complete());

        let fragments: Vec<U2FHIDFrame> = U2FHIDFrameIterator::new(&full).unwrap().collect();
        // 57, 59, 59, 59, 21
        assert_eq!(fragments.len(), 5);
        for f in &fragments {
            assert_eq!(f.cid, 1);
            assert!(!f.complete());
        }

        assert_eq!(fragments[0].cmd, 0x90);
        assert_eq!(fragments[0].len, 255);
        assert_eq!(fragments[0].data, (0..57).collect::<Vec<u8>>());
        assert_eq!(
            HidSendReportBytes::from(&fragments[0]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x90, // cmd
                0x00, 0xff, // len
                // payload
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38,
            ]
        );

        assert_eq!(fragments[1].cmd, 0);
        assert_eq!(fragments[1].data, (57..116).collect::<Vec<u8>>());
        assert_eq!(
            HidSendReportBytes::from(&fragments[1]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x00, // cmd
                // payload
                0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
                0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
                0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
                0x71, 0x72, 0x73,
            ]
        );

        assert_eq!(fragments[2].cmd, 1);
        assert_eq!(fragments[2].data, (116..175).collect::<Vec<u8>>());
        assert_eq!(
            HidSendReportBytes::from(&fragments[2]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x01, // cmd
                // payload
                0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
                0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
                0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
                0xac, 0xad, 0xae,
            ]
        );

        assert_eq!(fragments[3].cmd, 2);
        assert_eq!(fragments[3].data, (175..234).collect::<Vec<u8>>());
        assert_eq!(
            HidSendReportBytes::from(&fragments[3]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x02, // cmd
                // payload
                0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
                0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
                0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
                0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
                0xe7, 0xe8, 0xe9,
            ]
        );

        assert_eq!(fragments[4].cmd, 3);
        assert_eq!(fragments[4].data, (234..255).collect::<Vec<u8>>());
        assert_eq!(
            HidSendReportBytes::from(&fragments[4]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x03, // cmd
                // payload
                0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, //
                // padding
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );

        let assembled: U2FHIDFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
        assert!(assembled.complete());

        let mut p: U2FHIDFrame = fragments[0].clone() + fragments[1].clone();
        p += fragments[2].clone();
        p += fragments[3].clone();
        p += fragments[4].clone();
        assert_eq!(p, full);
        assert!(p.complete());
    }

    #[test]
    fn fragment_max_size() {
        // Maximum message size over U2F HID is 7609 bytes, this should encode
        // correctly.
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 7609,
            data: vec![0xFF; 7609],
        };

        let fragments: Vec<U2FHIDFrame> = U2FHIDFrameIterator::new(&full).unwrap().collect();
        assert_eq!(fragments.len(), 0x81);
        assert_eq!(fragments[0].cid, 1);
        assert_eq!(fragments[0].cmd, 0x90);
        assert_eq!(fragments[0].len, 7609);
        assert_eq!(fragments[0].data, [0xFF; 57]);

        assert_eq!(
            HidSendReportBytes::from(&fragments[0]),
            [
                0x00, // Report ID
                0x00, 0x00, 0x00, 0x01, // cid
                0x90, // cmd
                0x1d, 0xb9, // len
                // payload
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff
            ]
        );

        for f in &fragments[1..] {
            assert_eq!(f.cid, 1);
            assert_eq!(f.data, [0xFF; 59]);
            assert_eq!(f.len, 0);

            let b = HidSendReportBytes::from(f);
            // Report ID, CID
            assert_eq!(&b[..5], [0x00, 0x00, 0x00, 0x00, 0x01]);
            // Skip command ID
            // Payload
            assert_eq!(&b[6..], [0xFF; 59]);
        }

        // Reassembly
        let assembled: U2FHIDFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
        assert!(assembled.complete());

        // One more byte should error, and it shouldn't matter what `len` says
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 1,
            data: vec![0; 7609 + 1],
        };

        let err = U2FHIDFrameIterator::new(&full).err();
        assert_eq!(Some(WebauthnCError::MessageTooLarge), err);
    }
}
