//! [USBTransport] communicates with a FIDO token over USB HID, using [hidapi].
//!
//! This module should work on most platforms with USB support, provided that
//! the user has permissions.
//!
//! ## Windows support
//!
//! Windows' WebAuthn API (on Windows 10 build 1903 and later) blocks
//! non-Administrator access to **all** USB HID FIDO tokens, making them
//! invisible to normal USB HID APIs.
//!
//! Use [Win10][crate::win10::Win10] (available with the `win10` feature) on
//! Windows instead.
mod framing;
mod platform;
mod responses;

use crate::ctap2::CtapAuthenticator;
use crate::error::WebauthnCError;
use crate::transport::types::{KeepAliveStatus, Response, U2FHID_CANCEL, U2FHID_CBOR, U2FHID_INIT};
use crate::transport::*;
use crate::ui::UiCallback;
use crate::usb::framing::*;
use crate::usb::platform::traits::WatchEvent;
use async_trait::async_trait;
use futures::executor::block_on;
use futures::stream::BoxStream;
use futures::Stream;
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tokio::time::Interval;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{StreamMap, Timeout};

#[cfg(doc)]
use crate::stubs::*;

// use hidapi::{HidApi, HidDevice};
use openssl::rand::rand_bytes;
use std::fmt;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;
use webauthn_rs_proto::AuthenticatorTransport;

use self::platform::os::*;
use self::platform::traits::{USBDevice, USBDeviceInfo, USBDeviceManager};
pub(crate) use self::responses::InitResponse;

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const HID_RPT_SEND_SIZE: usize = HID_RPT_SIZE + 1;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

const CID_BROADCAST: u32 = 0xffffffff;

type HidReportBytes = [u8; HID_RPT_SIZE];
type HidSendReportBytes = [u8; HID_RPT_SEND_SIZE];

pub struct USBTransport {
    manager: USBDeviceManagerImpl,
    // api: HidApi,
}

pub struct USBToken {
    device: USBDeviceImpl,
    cid: u32,
    supports_ctap1: bool,
    supports_ctap2: bool,
    initialised: bool,
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
            .field("initialised", &self.initialised)
            .finish()
    }
}

impl USBTransport {
    pub fn new() -> Result<Self, WebauthnCError> {
        Ok(Self {
            manager: USBDeviceManager::new()?,
            // api: HidApi::new()?,
        })
    }
}

#[async_trait]
impl<'b> Transport<'b> for USBTransport {
    type Token = USBToken;

    async fn watch_tokens(&mut self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError> {
        let ret = self.manager.watch_devices().await?;

        Ok(Box::pin(ret.filter_map(|event| async move {
            trace!("watch_tokens event: {event:?}");
            match event {
                WatchEvent::Added(d) => {
                    if let Ok(dev) = d.open().await {
                        let mut token = USBToken::new(dev);
                        if let Ok(()) = token.init().await {
                            Some(TokenEvent::Added(token))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                WatchEvent::Removed(i) => Some(TokenEvent::Removed(i)),
                WatchEvent::EnumerationComplete => Some(TokenEvent::EnumerationComplete),
            }
        })))
    }

    /// Gets a list of attached USB HID FIDO tokens.
    ///
    /// Any un-openable devices will be silently ignored.
    ///
    /// ## Platform-specific issues
    ///
    /// ### Linux
    ///
    /// systemd (udev) v252 and later [automatically tag USB HID FIDO tokens][1]
    /// and set permissions based on the `f1d0` usage page, which should work
    /// with any FIDO-compliant token.
    ///
    /// Previously, most distributions used a fixed list of device IDs, which
    /// can be a problem for new or esoteric tokens.
    ///
    /// [1]: https://github.com/systemd/systemd/issues/11996
    ///
    /// ### Windows
    ///
    /// On Windows 10 build 1903 or later, this will not return any devices
    /// unless the program is run as Administrator.
    async fn get_devices(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        Ok(futures::stream::iter(self.manager.get_devices().await?)
            .filter_map(|d| async move {
                if let Ok(dev) = d.open().await {
                    Some(USBToken::new(dev))
                } else {
                    None
                }
            })
            .collect()
            .await)
    }
}

impl USBToken {
    fn new(device: USBDeviceImpl) -> Self {
        USBToken {
            device, // : Mutex::new(device),
            cid: 0,
            supports_ctap1: false,
            supports_ctap2: false,
            initialised: false,
        }
    }

    /// Sends a single [U2FHIDFrame] to the device, without fragmentation.
    async fn send_one(&mut self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        let d: HidSendReportBytes = frame.into();
        trace!(">>> {}", hex::encode(d));
        // let guard = self.device.lock()?;
        self.device.write(d).await?;
        Ok(())
    }

    /// Sends a [U2FHIDFrame] to the device, fragmenting the message to fit
    /// within the USB HID MTU.
    async fn send(&mut self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        for f in U2FHIDFrameIterator::new(frame)? {
            self.send_one(&f).await?;
        }
        Ok(())
    }

    /// Receives a single [U2FHIDFrame] from the device, without fragmentation.
    async fn recv_one(&mut self) -> Result<U2FHIDFrame, WebauthnCError> {
        let ret: HidReportBytes = async {
            // let guard = self.device.lock()?;
            let ret = self.device.read().await?;
            Ok::<HidReportBytes, WebauthnCError>(ret)
        }
        .await?;

        trace!("<<< {}", hex::encode(ret));
        U2FHIDFrame::try_from(&ret)
    }

    /// Recives a [Response] from the device, handling fragmented [U2FHIDFrame]
    /// responses if needed.
    async fn recv(&mut self) -> Result<Response, WebauthnCError> {
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
    // TODO: platform code
    type Id = <USBDeviceInfoImpl as USBDeviceInfo>::Id;

    async fn transmit_raw<U>(&mut self, cmd: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        if !self.initialised {
            error!("attempted to transmit to uninitialised token");
            return Err(WebauthnCError::Internal);
        }

        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: U2FHID_CBOR,
            len: cmd.len() as u16,
            data: cmd.to_vec(),
        };
        self.send(&cmd).await?;

        // Get a response, checking for keep-alive
        let resp = loop {
            let resp = self.recv().await?;

            if let Response::KeepAlive(r) = resp {
                trace!("waiting for {:?}", r);
                if r == KeepAliveStatus::UserPresenceNeeded {
                    ui.request_touch();
                }
                // TODO: maybe time out at some point
                tokio::time::sleep(Duration::from_millis(100)).await;
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
        if self.initialised {
            warn!("attempted to init an already-initialised token");
            return Ok(())
        }

        // Setup a channel to communicate with the device (CTAPHID_INIT).
        let mut nonce: [u8; 8] = [0; 8];
        rand_bytes(&mut nonce)?;

        self.send(&U2FHIDFrame {
            cid: CID_BROADCAST,
            cmd: U2FHID_INIT,
            len: nonce.len() as u16,
            data: nonce.to_vec(),
        })
        .await?;

        match self.recv().await? {
            Response::Init(i) => {
                trace!(?i);
                assert_eq!(&nonce, &i.nonce[..]);
                self.cid = i.cid;
                self.supports_ctap1 = i.supports_ctap1();
                self.supports_ctap2 = i.supports_ctap2();

                if self.supports_ctap2 {
                    self.initialised = true;
                    Ok(())
                } else {
                    error!("token does not support CTAP 2");
                    Err(WebauthnCError::NotSupported)
                }
            }
            e => {
                error!("Unhandled response type: {:?}", e);
                Err(WebauthnCError::Internal)
            }
        }
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        Ok(())
    }

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Usb
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        if !self.initialised {
            error!("attempted to cancel uninitialised token");
            return Err(WebauthnCError::Internal);
        }

        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: U2FHID_CANCEL,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await
    }
}
