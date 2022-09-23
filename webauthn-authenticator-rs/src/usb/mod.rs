//! [USBTransport] communicates with a FIDO token over USB HID, using [hidapi].
//!
//! This module should work on most platforms with USB support, provided that
//! the user has permissions.
//!
//! **Note:** Windows' WebAuthn API (on Windows 10 build 1903 and later) blocks
//! non-Administrator access to all USB HID FIDO tokens, making them invisible
//! to normal USB HID APIs.
mod framing;
mod responses;

use crate::cbor::*;
use crate::error::WebauthnCError;
use crate::transport::*;
use crate::usb::framing::*;
use crate::usb::responses::*;
use hidapi::{HidApi, HidDevice};
use openssl::rand::rand_bytes;
use std::fmt;

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

const TYPE_INIT: u8 = 0x80;
const U2FHID_MSG: u8 = TYPE_INIT | 0x03;
const U2FHID_INIT: u8 = TYPE_INIT | 0x06;
const U2FHID_CBOR: u8 = TYPE_INIT | 0x10;
const U2FHID_ERROR: u8 = TYPE_INIT | 0x3f;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const CID_BROADCAST: u32 = 0xffffffff;

pub struct USBTransport {
    api: HidApi,
}

pub struct USBToken {
    device: HidDevice,
    cid: u32,
    supports_ctap1: bool,
    supports_ctap2: bool,
}

impl fmt::Debug for USBTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBTransport").finish()
    }
}

impl fmt::Debug for USBToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBToken")
            .field("cid", &self.cid)
            .field("supports_ctap1", &self.supports_ctap1)
            .field("supports_ctap2", &self.supports_ctap2)
            .finish()
    }
}

impl Default for USBTransport {
    fn default() -> Self {
        Self {
            api: HidApi::new().expect("Error initializing USB HID API"),
        }
    }
}

impl Transport for USBTransport {
    type Token = USBToken;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        Ok(self
            .api
            .device_list()
            .filter(|d| d.usage_page() == FIDO_USAGE_PAGE && d.usage() == FIDO_USAGE_U2FHID)
            .map(|d| {
                trace!(?d);
                d
            })
            .map(|d| d.open_device(&self.api).expect("Could not open device"))
            .map(USBToken::new)
            .collect())
    }
}

impl USBToken {
    fn new(device: HidDevice) -> Self {
        USBToken {
            device,
            cid: 0,
            supports_ctap1: false,
            supports_ctap2: false,
        }
    }

    /// Sends a single [U2FHIDFrame] to the device, without fragmentation.
    fn send_one(&self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        let d: Vec<u8> = frame.into();
        trace!(">>> {:02x?}", d);
        self.device
            .write(&d)
            .map_err(|_| WebauthnCError::ApduTransmission)
            .map(|_| ())
    }

    /// Sends a [U2FHIDFrame] to the device, fragmenting the message to fit
    /// within the USB HID MTU.
    fn send(&self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        for f in U2FHIDFrameIterator::new(frame)? {
            self.send_one(&f)?;
        }
        Ok(())
    }

    /// Receives a single [U2FHIDFrame] from the device, without fragmentation.
    fn recv_one(&self) -> Result<U2FHIDFrame, WebauthnCError> {
        let mut ret: Vec<u8> = vec![0; HID_RPT_SIZE];

        let len = self
            .device
            .read_timeout(&mut ret, U2FHID_TRANS_TIMEOUT)
            .map_err(|_| WebauthnCError::ApduTransmission)?;

        trace!("<<< {:02x?}", &ret[..len]);
        U2FHIDFrame::try_from(&ret[..len])
    }

    /// Recives a [Response] from the device, handling fragmented [U2FHIDFrame]
    /// responses if needed.
    fn recv(&self) -> Result<Response, WebauthnCError> {
        // Recieve first chunk
        let mut f = self.recv_one()?;
        let mut s: usize = f.data.len();
        let t = usize::from(f.len);

        // Get more chunks, if needed
        while s < t {
            let n = self.recv_one()?;
            s += n.data.len();
            f += n;
        }
        Response::try_from(&f)
    }
}

impl Token for USBToken {
    fn transmit<'a, C, R>(&self, cmd: C) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        let cbor = cmd.cbor().map_err(|_| WebauthnCError::Cbor)?;
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: U2FHID_CBOR,
            len: cbor.len() as u16,
            data: cbor,
        };
        self.send(&cmd)?;

        // Get a response
        match self.recv()? {
            Response::Cbor(c) => R::try_from(&c.data).map_err(|_| WebauthnCError::Cbor),
            e => {
                error!("Unhandled response type: {:?}", e);
                Err(WebauthnCError::Cbor)
            }
        }
    }

    fn init(&mut self) -> Result<(), WebauthnCError> {
        // Setup a channel to communicate with the device (CTAPHID_INIT).
        let mut nonce: [u8; 8] = [0; 8];
        rand_bytes(&mut nonce).map_err(|_| WebauthnCError::OpenSSL)?;

        self.send(&U2FHIDFrame {
            cid: CID_BROADCAST,
            cmd: U2FHID_INIT,
            len: nonce.len() as u16,
            data: nonce.to_vec(),
        })?;

        match self.recv()? {
            Response::Init(i) => {
                trace!(?i);
                assert_eq!(&nonce, &i.nonce[..]);
                self.cid = i.cid;
                self.supports_ctap1 = i.supports_ctap1();
                self.supports_ctap2 = i.supports_ctap2();
                Ok(())
            }
            e => {
                error!("Unhandled response type: {:?}", e);
                Err(WebauthnCError::Internal)
            }
        }
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        Ok(())
    }
}
