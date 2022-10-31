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

use crate::ctap2::*;
use crate::error::WebauthnCError;
use crate::transport::*;
use crate::ui::UiCallback;
use crate::usb::framing::*;
use crate::usb::responses::*;
use async_trait::async_trait;
use hidapi::{HidApi, HidDevice};
use openssl::rand::rand_bytes;
use std::fmt;
use std::ops::Deref;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use webauthn_rs_proto::AuthenticatorTransport;

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const HID_RPT_SEND_SIZE: usize = HID_RPT_SIZE + 1;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

const TYPE_INIT: u8 = 0x80;
const U2FHID_MSG: u8 = TYPE_INIT | 0x03;
const U2FHID_INIT: u8 = TYPE_INIT | 0x06;
const U2FHID_CBOR: u8 = TYPE_INIT | 0x10;
const U2FHID_CANCEL: u8 = TYPE_INIT | 0x11;
const U2FHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b;
const U2FHID_ERROR: u8 = TYPE_INIT | 0x3f;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const CID_BROADCAST: u32 = 0xffffffff;

type HidReportBytes = [u8; HID_RPT_SIZE];
type HidSendReportBytes = [u8; HID_RPT_SEND_SIZE];

pub struct USBTransport {
    api: HidApi,
}

pub struct USBToken {
    device: Mutex<HidDevice>,
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

impl<'b> Transport<'b> for USBTransport {
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
            device: Mutex::new(device),
            cid: 0,
            supports_ctap1: false,
            supports_ctap2: false,
        }
    }

    /// Sends a single [U2FHIDFrame] to the device, without fragmentation.
    fn send_one(&self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        let d: HidSendReportBytes = frame.into();
        trace!(">>> {:02x?}", d);
        let guard = self.device.lock().unwrap();
        guard
            .deref()
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
    async fn recv_one(&self) -> Result<U2FHIDFrame, WebauthnCError> {
        let ret: HidReportBytes = async {
            let mut ret: HidReportBytes = [0; HID_RPT_SIZE];
            let guard = self.device.lock().unwrap();
            guard
                .deref()
                .read_timeout(&mut ret, U2FHID_TRANS_TIMEOUT)
                .map_err(|_| WebauthnCError::ApduTransmission)?;
            Ok::<HidReportBytes, WebauthnCError>(ret)
        }
        .await?;

        trace!("<<< {:02x?}", &ret);
        U2FHIDFrame::try_from(&ret)
    }

    /// Recives a [Response] from the device, handling fragmented [U2FHIDFrame]
    /// responses if needed.
    async fn recv(&self) -> Result<Response, WebauthnCError> {
        // Recieve first chunk
        let mut f = self.recv_one().await?;
        let mut s: usize = f.data.len();
        let t = usize::from(f.len);

        // Get more chunks, if needed
        while s < t {
            let n = self.recv_one().await?;
            s += n.data.len();
            f += n;
        }
        Response::try_from(&f)
    }
}

#[async_trait]
impl Token for USBToken {
    async fn transmit_raw<C, U>(&self, cmd: C, ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        C: CBORCommand,
        U: UiCallback,
    {
        let cbor = cmd.cbor().map_err(|_| WebauthnCError::Cbor)?;
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: U2FHID_CBOR,
            len: cbor.len() as u16,
            data: cbor,
        };
        self.send(&cmd)?;

        // Get a response, checking for keep-alive
        let resp = loop {
            let resp = self.recv().await?;

            if let Response::KeepAlive(r) = resp {
                trace!("waiting for {:?}", r);
                if r == KeepAliveStatus::UserPresenceNeeded {
                    ui.request_touch();
                }
                // TODO: maybe time out at some point
                thread::sleep(Duration::from_millis(100));
            } else {
                break resp;
            }
        };

        // Get a response
        match resp {
            Response::Cbor(c) => {
                if c.status.is_ok() {
                    Ok(c.data)
                } else {
                    let e = WebauthnCError::Ctap(c.status);
                    error!("Ctap error: {:?}", e);
                    Err(e)
                }
            }
            e => {
                error!("Unhandled response type: {:?}", e);
                Err(WebauthnCError::Cbor)
            }
        }
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        // Setup a channel to communicate with the device (CTAPHID_INIT).
        let mut nonce: [u8; 8] = [0; 8];
        rand_bytes(&mut nonce)?;

        self.send(&U2FHIDFrame {
            cid: CID_BROADCAST,
            cmd: U2FHID_INIT,
            len: nonce.len() as u16,
            data: nonce.to_vec(),
        })?;

        match self.recv().await? {
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

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Usb
    }

    fn cancel(&self) -> Result<(), WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: U2FHID_CANCEL,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd)
    }
}
