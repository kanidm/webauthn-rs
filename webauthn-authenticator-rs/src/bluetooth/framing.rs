//! Helpers for framing Bluetooth Low Energy messages.
//!

use crate::error::WebauthnCError;
use std::cmp::min;
use std::iter::Sum;

use super::VALID_MTU_RANGE;

const INITIAL_FRAGMENT_HEADER: usize = 3;
const CONTINUATION_FRAGMENT_HEADER: usize = 1;
const CONTINUATION_FRAGMENT_COUNT: usize = 0x80;

/// Bluetooth Low Energy frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtleFrame {
    /// Command identifier or status code
    pub cmd: u8,
    /// Complete length of the frame when unfragmented.
    ///
    /// This will exceed the length of [`BtleFrame::data`] for for the initial
    /// fragement of a fragmented frame.
    ///
    /// This is set to 0 for continuation fragments.
    pub len: u16,
    /// Data payload, of up to [`BtleFrame::len`] bytes.
    pub data: Vec<u8>,
}

impl BtleFrame {
    /// Returns `true` if this is an initial frame.
    fn is_initial(&self) -> bool {
        self.cmd & 0x80 != 0
    }

    /// Returns the length of the header, in bytes.
    fn header_length(&self) -> usize {
        if self.is_initial() {
            INITIAL_FRAGMENT_HEADER
        } else {
            CONTINUATION_FRAGMENT_HEADER
        }
    }

    /// Returns `true` if the frame is an initial fragment and
    /// [Self::len] == 0 or [Self::data.len].
    ///
    /// Frames fragmented by [BtleFrameIterator] return `false`.
    ///
    /// Frames that have been _partially_ or _fully_ reassembled by [Sum] return
    /// `true`.
    pub fn complete(&self) -> bool {
        self.is_initial() && (self.len == 0 || self.data.len() == usize::from(self.len))
    }

    /// Serialises a [BtleFrame] to bytes to be sent via a BTLE GATT attribute.
    ///
    /// This does not fragment packets: see [BtleFrameIterator].
    ///
    /// # Errors
    ///
    /// * [`InvalidMessageLength`] if the `mtu` is not in [VALID_MTU_RANGE]
    /// * [`MessageTooLarge`] if the message is too large for the `mtu`
    ///
    /// [`InvalidMessageLength`]: WebauthnCError::InvalidMessageLength
    /// [`MessageTooLarge`]: WebauthnCError::MessageTooLarge
    pub fn as_vec(&self, mtu: usize) -> Result<Vec<u8>, WebauthnCError> {
        if !VALID_MTU_RANGE.contains(&mtu) {
            return Err(WebauthnCError::InvalidMessageLength);
        }
        if mtu < self.header_length() + self.data.len() {
            return Err(WebauthnCError::MessageTooLarge);
        }
        let mut o: Vec<u8> = Vec::with_capacity(mtu);

        o.push(self.cmd);
        if self.is_initial() {
            o.extend_from_slice(&self.len.to_be_bytes());
        }
        o.extend_from_slice(&self.data);

        Ok(o)
    }
}

const EMPTY_FRAME: BtleFrame = BtleFrame {
    cmd: 0,
    len: 0,
    data: vec![],
};

/// Iterator type for fragmenting a long [BtleFrame] into smaller pieces that
/// fit within the BTLE GATT MTU.
pub struct BtleFrameIterator<'a> {
    /// The frame to fragment.
    f: &'a BtleFrame,
    /// The current position within the frame we're up to.
    p: &'a [u8],
    /// The fragment number we're up to.
    i: u8,
    /// If we've done the first iteration.
    s: bool,
    /// The MTU for messages to the device (`controlPointLength`)
    mtu: usize,
}

impl<'a> BtleFrameIterator<'a> {
    /// Creates a new iterator for fragmenting [BtleFrame]
    pub fn new(f: &'a BtleFrame, mtu: usize) -> Result<Self, WebauthnCError> {
        if !VALID_MTU_RANGE.contains(&mtu) {
            return Err(WebauthnCError::InvalidMessageLength);
        }
        let max_size = min(
            u16::MAX.into(),
            (mtu - INITIAL_FRAGMENT_HEADER)
                + (CONTINUATION_FRAGMENT_COUNT * (mtu - CONTINUATION_FRAGMENT_HEADER)),
        );
        if f.data.len() > max_size {
            return Err(WebauthnCError::MessageTooLarge);
        }
        Ok(BtleFrameIterator {
            f,
            p: &f.data,
            i: 0,
            s: false,
            mtu,
        })
    }
}

impl Iterator for BtleFrameIterator<'_> {
    type Item = BtleFrame;

    fn next(&mut self) -> Option<Self::Item> {
        let l = self.p.len();
        let (data, p) = self.p.split_at(min(
            l,
            self.mtu
                - if self.s {
                    CONTINUATION_FRAGMENT_HEADER
                } else {
                    INITIAL_FRAGMENT_HEADER
                },
        ));
        self.p = p;

        if !self.s {
            // First round
            self.s = true;
            Some(BtleFrame {
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
            Some(BtleFrame {
                cmd: i,
                len: 0,
                data: data.to_vec(),
            })
        }
    }
}

/// Merges fragmented [BtleFrame]s back together. Assumes the first element
/// is the initial fragment. Order of subsequent fragments doesn't matter.
impl<'a> Sum<&'a BtleFrame> for BtleFrame {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        // First frame
        let mut s: Option<&Self> = None;
        let mut initial_fragment_size = 0usize;
        let mut fragment_size = 0usize;
        let mut o: Vec<u8> = Vec::with_capacity(0);

        for f in iter {
            match &s {
                None => {
                    o = vec![0; usize::from(f.len)];
                    initial_fragment_size = f.data.len();
                    fragment_size = initial_fragment_size + 2;
                    let p = min(f.data.len(), usize::from(f.len));
                    o[..p].copy_from_slice(&f.data[..p]);
                    s = Some(f);
                }

                Some(first) => {
                    let p = initial_fragment_size + (usize::from(f.cmd) * fragment_size);
                    let q = min(p + f.data.len(), usize::from(first.len));
                    o[p..q].copy_from_slice(&f.data[..q - p]);
                }
            }
        }
        match s {
            Some(first) => BtleFrame { data: o, ..*first },
            None => EMPTY_FRAME,
        }
    }
}

/// Deserialises bytes from a Bluetooth GATT notification into a [BtleFrame].
impl TryFrom<&[u8]> for BtleFrame {
    type Error = WebauthnCError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let mut o = Self {
            cmd: b[0],
            ..Default::default()
        };
        let b = &b[1..];
        if o.is_initial() {
            // Initial
            let (len, b) = b.split_at(2);
            o.len = u16::from_be_bytes(
                len.try_into()
                    .map_err(|_| WebauthnCError::MessageTooShort)?,
            );
            // Resize the buffer for short messages
            o.data = b[..min(b.len(), usize::from(o.len))].to_vec();
        } else {
            // Continuation
            o.data = b.to_vec();
        }
        Ok(o)
    }
}

#[cfg(test)]
mod test {
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn dont_malloc_huge_mtu() {
        let frame = BtleFrame {
            cmd: 0x80,
            len: 1,
            data: vec![0xFF; 1],
        };

        assert!(frame.complete());
        assert!(frame.is_initial());
        assert_eq!(
            frame.as_vec(usize::MAX),
            Err(WebauthnCError::InvalidMessageLength)
        );
        assert_eq!(
            frame.as_vec(u32::MAX as usize),
            Err(WebauthnCError::InvalidMessageLength)
        );
    }

    #[test]
    fn initial_frame_minimum_size() {
        // Minimum sized initial frame
        let frame = BtleFrame {
            cmd: 0x80,
            len: 17,
            data: vec![0xFF; 17],
        };
        let expected = vec![
            0x80, 0x00, 0x11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert!(frame.complete());
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());

        // Invalid MTUs
        for mtu in (0..=19).chain([513].into_iter()) {
            assert_eq!(
                frame.as_vec(mtu),
                Err(WebauthnCError::InvalidMessageLength),
                "BtleFrame.as_vec should reject MTU of {mtu}"
            );
        }
    }
    #[test]
    fn initial_frame_needing_fragmentation() {
        // Longer initial frame should fail at small MTUs without fragmentation
        let frame = BtleFrame {
            cmd: 0x80,
            len: 18,
            data: vec![0xFF; 18],
        };
        let expected = vec![
            0x80, 0x00, 0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert!(frame.complete());
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20), Err(WebauthnCError::MessageTooLarge));
        assert_eq!(frame.as_vec(21).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());
    }

    #[test]
    fn small_initial_frame_checks_mtu() {
        // Even when the data is small enough, it should fail at small MTUs
        let frame = BtleFrame {
            cmd: 0x80,
            len: 1,
            data: vec![0xFF; 1],
        };
        let expected = vec![0x80, 0x00, 0x01, 0xff];

        assert!(frame.complete());
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());

        // Invalid MTUs
        for mtu in (0..=19).chain([513].into_iter()) {
            assert_eq!(
                frame.as_vec(mtu),
                Err(WebauthnCError::InvalidMessageLength),
                "BtleFrame.as_vec should reject MTU of {mtu}"
            );
        }
    }

    #[test]
    fn frame_len_attribute_is_authoritative() {
        // BtleFrameIterator puts in a proper length for us when fragmenting,
        // and it is unset on continuation frames, so that the len attribute
        // should be authoritative.
        let frame = BtleFrame {
            cmd: 0x80,
            len: 0,
            data: vec![0xFF; 1],
        };
        let expected = vec![0x80, 0x00, 0x00, 0xff];

        assert!(frame.complete()); // because ==0
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        // Should drop the excess bytes for a zero-length frame...
        assert_eq!(
            BtleFrame {
                data: vec![],
                ..frame
            },
            BtleFrame::try_from(expected.as_slice()).unwrap()
        );

        // Technically invalid...
        let frame = BtleFrame {
            cmd: 0x80,
            len: 2,
            data: vec![0xFF; 1],
        };
        let expected = vec![0x80, 0x00, 0x02, 0xff];

        assert!(!frame.complete()); // because !=0 and !=len
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        // Keep the partial bytes
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());
    }

    #[test]
    fn contination_frame_minimum_size() {
        // Minimum sized continuation frame
        let frame = BtleFrame {
            cmd: 0x01,
            len: 0,
            data: vec![0xFF; 19],
        };
        let expected = vec![
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert!(!frame.complete());
        assert!(!frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());

        // Invalid MTUs
        for mtu in (0..=19).chain([513].into_iter()) {
            assert_eq!(
                frame.as_vec(mtu),
                Err(WebauthnCError::InvalidMessageLength),
                "BtleFrame.as_vec should reject MTU of {mtu}"
            );
        }
    }

    #[test]
    fn contination_frame_needing_fragmentation() {
        // Longer continuation frame should fail at small MTUs without
        // fragmentation
        let frame = BtleFrame {
            cmd: 0x01,
            len: 0,
            data: vec![0xFF; 20],
        };
        let expected = vec![
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert!(!frame.complete());
        assert!(!frame.is_initial());
        assert_eq!(frame.as_vec(20), Err(WebauthnCError::MessageTooLarge));
        assert_eq!(frame.as_vec(21).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());
    }

    #[test]
    fn small_continuation_frame_checks_mtu() {
        // Even when the data is small enough, it should fail at small MTUs
        let frame = BtleFrame {
            cmd: 0x01,
            len: 0,
            data: vec![0xFF; 1],
        };
        let expected = vec![0x01, 0xff];

        assert!(!frame.complete());
        assert!(!frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());

        // Invalid MTUs
        for mtu in (0..=19).chain([513].into_iter()) {
            assert_eq!(
                frame.as_vec(mtu),
                Err(WebauthnCError::InvalidMessageLength),
                "BtleFrame.as_vec should reject MTU of {mtu}"
            );
        }
    }

    #[test]
    fn incomplete_initial_frame() {
        let frame = BtleFrame {
            cmd: 0x80,
            len: 512,
            data: vec![0xFF; 17],
        };
        let expected = vec![
            0x80, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert!(!frame.complete());
        assert!(frame.is_initial());
        assert_eq!(frame.as_vec(20).unwrap(), expected);
        assert_eq!(frame.as_vec(512).unwrap(), expected);
        assert_eq!(frame, BtleFrame::try_from(expected.as_slice()).unwrap());
    }

    #[test]
    fn fragment_short() {
        let full = BtleFrame {
            cmd: 0x81,
            len: 2,
            data: vec![1, 2],
        };

        let fragments: Vec<BtleFrame> = BtleFrameIterator::new(&full, 20).unwrap().collect();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], full);

        let assembled: BtleFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
    }

    #[test]
    fn fragment_small_mtu() {
        let full = BtleFrame {
            cmd: 0x81,
            len: 40,
            data: (0..40).collect(),
        };
        assert!(full.complete());

        let mtu = 20;
        let mut fragments: VecDeque<BtleFrame> =
            BtleFrameIterator::new(&full, mtu).unwrap().collect();
        let mut parsed: Vec<BtleFrame> = Vec::with_capacity(3);
        // 17, 19, 4
        assert_eq!(fragments.len(), 3);
        for f in &fragments {
            assert!(!f.complete());
        }

        let f = fragments.pop_front().unwrap();
        assert_eq!(f.cmd, 0x81);
        assert_eq!(f.len, 0x28);
        assert_eq!(f.data, (0..17).collect::<Vec<u8>>());
        let c = f.as_vec(mtu).unwrap();
        assert_eq!(
            c,
            vec![
                0x81, // cmd
                0x00, 0x28, // len
                // payload
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10
            ]
        );
        parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());

        let f = fragments.pop_front().unwrap();
        assert_eq!(f.cmd, 0);
        assert_eq!(f.data, (17..36).collect::<Vec<u8>>());
        let c = f.as_vec(mtu).unwrap();
        assert_eq!(
            c,
            vec![
                0x00, // cmd
                // payload
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                0x1f, 0x20, 0x21, 0x22, 0x23,
            ]
        );
        parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());

        let f = fragments.pop_front().unwrap();
        assert_eq!(f.cmd, 1);
        assert_eq!(f.data, (36..40).collect::<Vec<u8>>());
        let c = f.as_vec(mtu).unwrap();
        assert_eq!(
            c,
            vec![
                0x01, // cmd
                // payload
                0x24, 0x25, 0x26, 0x27
            ]
        );
        parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());

        let assembled: BtleFrame = parsed.iter().sum();
        assert_eq!(assembled, full);
        assert!(assembled.complete());
    }

    #[test]
    fn fragment_large_mtu() {
        let full = BtleFrame {
            cmd: 0x81,
            len: 400,
            data: vec![0xff; 400],
        };
        assert!(full.complete());

        let mtu = 512;
        let mut fragments: VecDeque<BtleFrame> =
            BtleFrameIterator::new(&full, mtu).unwrap().collect();
        let mut parsed: Vec<BtleFrame> = Vec::with_capacity(1);
        // 400
        assert_eq!(fragments.len(), 1);

        let f = fragments.pop_front().unwrap();
        assert_eq!(f.cmd, 0x81);
        assert_eq!(f.len, 0x190);
        assert_eq!(f.data, vec![0xff; 400]);
        let c = f.as_vec(mtu).unwrap();
        assert_eq!(
            c,
            vec![
                0x81, // cmd
                0x01, 0x90, // len
                // payload
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ]
        );

        parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());
        let assembled: BtleFrame = parsed.iter().sum();
        assert_eq!(assembled, full);
        assert!(assembled.complete());
    }

    #[test]
    fn iterator_invalid_mtus() {
        let frame = BtleFrame {
            cmd: 0x80,
            len: 1,
            data: vec![0xFF; 1],
        };

        for mtu in (0..=19).chain([513].into_iter()) {
            assert_eq!(
                BtleFrameIterator::new(&frame, mtu).err(),
                Some(WebauthnCError::InvalidMessageLength),
                "BtleFrameIterator should reject MTU of {mtu}"
            );
        }
    }

    macro_rules! fragment_max_mtu {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (mtu, max_size): (usize, usize) = $value;
                let full = BtleFrame {
                    cmd: 0x90,
                    len: max_size as u16,
                    data: vec![0xFF; max_size],
                };

                let mut fragments: VecDeque<BtleFrame> =
                    BtleFrameIterator::new(&full, mtu).unwrap().collect();
                let mut parsed: Vec<BtleFrame> = Vec::with_capacity(0x81);

                assert_eq!(fragments.len(), 0x81, "expected 0x81 fragments, max_size is not the maximum");

                let f = fragments.pop_front().unwrap();
                assert_eq!(f.cmd, 0x90);
                assert_eq!(f.len, max_size as u16);
                assert_eq!(f.data, vec![0xff; mtu - 3]);
                let c = f.as_vec(mtu).unwrap();
                assert_eq!(c.len(), mtu);
                assert!(c[3..].iter().all(|v| *v == 0xff));
                parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());

                for f in fragments {
                    assert_eq!(f.len, 0);
                    assert!(f.data.iter().all(|v| *v == 0xff));

                    let c = f.as_vec(mtu).unwrap();
                    assert!(c[1..].iter().all(|v| *v == 0xff));
                    parsed.push(BtleFrame::try_from(c.as_slice()).unwrap());
                }

                // Reassembly
                let assembled: BtleFrame = parsed.iter().sum();
                assert_eq!(assembled, full);
                assert!(assembled.complete());

                // One more byte should error, and it shouldn't matter what `len` says
                let full = BtleFrame {
                    cmd: 0x90,
                    len: 1,
                    data: vec![0; max_size + 1],
                };

                let err = BtleFrameIterator::new(&full, mtu).err();
                assert_eq!(Some(WebauthnCError::MessageTooLarge), err, "expected max_size + 1 to error, max_size is not the maximum");
            }
        )*
        }
    }

    fragment_max_mtu! {
        fragment_max_mtu_20: (20, 2449),
        fragment_max_mtu_509: (509, 65530),
        // Limited by message length (u16)
        fragment_max_mtu_510: (510, 65535),
        fragment_max_mtu_512: (512, 65535),
    }
}
