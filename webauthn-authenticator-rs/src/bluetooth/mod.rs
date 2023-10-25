//! [BluetoothTransport] communicates with a FIDO token over Bluetooth Low
//! Energy, using [btleplug].
//!
//! This module should work on most platforms with Bluetooth Low Energy support,
//! provided that the user has permissions.
//!
//! ## Warning
//!
//! There are [API design issues][0] with [Transport] which make
//! [BluetoothTransport] **extremely** flaky and timing sensitive. These have
//! been partially addressed, but there is still some way to go.
//!
//! The [long term goal][0] is that this API (and its UI) will become as easy to
//! use as Windows WebAuthn API, but it's not there just yet.
//!
//! [0]: https://github.com/kanidm/webauthn-rs/issues/214
//!
//! ## caBLE support
//!
//! To use a caBLE / hybrid authenticator, use the [cable][crate::cable] module
//! (avaliable with `--features cable`) instead.
//!
//! ## Linux support
//!
//! Seems to be extremely flakey.
//!
//! ## macOS support
//!
//! Works fine.
//!
//! Non-paired (but discoverable) Bluetooth FIDO tokens do not appear in the
//! System Settings Bluetooth pane – it can only be triggered by an application
//! attempting to connect to an authenticator.
//!
//! This will attempt to connect to any nearby FIDO token.
//!
//! ## Windows support
//!
//! Windows' WebAuthn API (on Windows 10 build 1903 and later) blocks
//! non-Administrator access to BTLE FIDO tokens, and will return "permission
//! denied" errors when accessed via normal Bluetooth APIs. This does not impact
//! use of caBLE authenticators.
//!
//! Use [Win10][crate::win10::Win10] (available with `--features win10`) on
//! Windows instead.
//!
//! You'll need to manually pair your authenticator in Device Manager before
//! using it with this or Windows' WebAuthn API.
use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    pin::Pin,
    time::{Duration, Instant},
};

#[cfg(doc)]
use crate::stubs::*;

use async_trait::async_trait;
use btleplug::{
    api::{
        bleuuid::uuid_from_u16, Central, CentralEvent, Characteristic, Manager as _,
        Peripheral as _, ScanFilter, WriteType,
    },
    platform::{Manager, Peripheral, PeripheralId},
};
use futures::{executor::block_on, stream::BoxStream, Stream, StreamExt};
use tokio::{sync::mpsc, task::spawn};
use tokio_stream::wrappers::ReceiverStream;
use uuid::{uuid, Uuid};
use webauthn_rs_proto::AuthenticatorTransport;

use crate::{
    error::WebauthnCError,
    transport::{
        types::{
            CBORResponse, KeepAliveStatus, Response, U2FError, BTLE_CANCEL, BTLE_KEEPALIVE,
            U2FHID_ERROR, U2FHID_MSG, U2FHID_PING,
        },
        Token, TokenEvent, Transport, TYPE_INIT,
    },
    ui::UiCallback,
};

use self::framing::{BtleFrame, BtleFrameIterator};

mod framing;

/// The FIDO Bluetooth GATT [Service] [Uuid].
///
/// Reference: [Bluetooth Assigned Numbers][], Section 3.10 (SDO Services)
///
/// [Bluetooth Assigned Numbers]: https://www.bluetooth.com/specifications/assigned-numbers/
/// [Service]: btleplug::api::Service
const FIDO_GATT_SERVICE: Uuid = uuid_from_u16(0xfffd);

/// FIDO Control Point [Characteristic] [Uuid].
///
/// This is a write-only command buffer for the initiator.
const FIDO_CONTROL_POINT: Uuid = uuid!("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB");

/// FIDO Status [Characteristic] [Uuid].
///
/// The authenticator sends notifications to respond to commands sent to
/// [FIDO_CONTROL_POINT].
const FIDO_STATUS: Uuid = uuid!("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB");

/// FIDO Control Point Length [Characteristic] [Uuid].
///
/// This is a read-only value in [VALID_MTU_RANGE] which indicates the MTU of
/// the [FIDO_CONTROL_POINT] and [FIDO_STATUS] [Characteristic]s.
const FIDO_CONTROL_POINT_LENGTH: Uuid = uuid!("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB");

/// FIDO Service Revision Bitfield [Characteristic] [Uuid].
///
/// When read by the initiator, the authenticator sends which protocol versions
/// are supported as a bitfield, and then the initiator writes a single bit
/// indicating which protocol it will use.
///
/// This is not present on U2F 1.0 authenticators.
const FIDO_SERVICE_REVISION_BITFIELD: Uuid = uuid!("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB");

/// Valid MTU range for [FIDO_CONTROL_POINT_LENGTH].
const VALID_MTU_RANGE: RangeInclusive<usize> = 20..=512;

/// Bitfield value in [FIDO_SERVICE_REVISION_BITFIELD] to indicate an
/// authenticator supports CTAP2.
const SERVICE_REVISION_CTAP2: u8 = 0x20;

pub struct BluetoothDeviceWatcher {
    // transport: &'a BluetoothTransport,
    stream: ReceiverStream<TokenEvent<BluetoothToken>>,
}

impl BluetoothDeviceWatcher {
    async fn new(
        transport: &BluetoothTransport,
        debounce: Duration,
    ) -> Result<BluetoothDeviceWatcher, WebauthnCError> {
        let (tx, rx) = mpsc::channel(16);
        let stream = ReceiverStream::from(rx);

        let adapters = transport.manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or(WebauthnCError::NoBluetoothAdapter)?;

        let filter = ScanFilter {
            services: vec![FIDO_GATT_SERVICE],
        };
        adapter.start_scan(filter).await?;

        let mut events = adapter.events().await?;
        if let Err(e) = tx.send(TokenEvent::EnumerationComplete).await {
            error!("could not send Bluetooth EnumerationComplete: {e:?}");
            return Err(WebauthnCError::Internal);
        }

        spawn(async move {
            // We need to track recently connected devices so that we don't get
            // stuck in loops. There's also Hideez which continues transmitting
            // advertisements for 30 seconds after use, even when the LED is
            // off...
            let mut recents: HashMap<PeripheralId, Instant> = HashMap::new();
            let mut connected = HashSet::new();
            while let Some(event) = events.next().await {
                if tx.is_closed() {
                    break;
                }
                match event {
                    CentralEvent::DeviceConnected(id) => {
                        trace!("device connected: {id:?}");
                        let peripheral = match adapter.peripheral(&id).await {
                            Ok(p) => p,
                            Err(e) => {
                                error!("could not get info for BTLE peripheral {id:?}: {e:?}");
                                continue;
                            }
                        };

                        let properties = match peripheral.properties().await {
                            Ok(Some(p)) => p,
                            Ok(None) => {
                                error!(
                                    "no properties available for BTLE peripheral {id:?}, ignoring"
                                );
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "could not get properties for BTLE peripheral {id:?}: {e:?}"
                                );
                                continue;
                            }
                        };

                        if !properties.services.contains(&FIDO_GATT_SERVICE) {
                            trace!("BTLE peripheral {id:?} is not a FIDO token, skipping");
                            continue;
                        }

                        connected.insert(id);
                        if tx
                            .send(TokenEvent::Added(BluetoothToken::new(peripheral)))
                            .await
                            .is_err()
                        {
                            // channel lost!
                            break;
                        }
                    }

                    CentralEvent::DeviceDisconnected(id) => {
                        trace!("device disconnected: {id:?}");
                        if !connected.remove(&id) {
                            // Don't notify about the same device twice
                            continue;
                        }

                        if tx.send(TokenEvent::Removed(id)).await.is_err() {
                            // channel lost!
                            break;
                        }
                    }

                    CentralEvent::DeviceDiscovered(id) => {
                        trace!("device discovered: {id:?}");
                        if let Some(last_seen) = recents.get(&id) {
                            if last_seen.elapsed() < debounce {
                                trace!("ignoring recently-seen device: {id:?}");
                                recents.insert(id, Instant::now());
                                continue;
                            }

                            recents.remove(&id);
                        }

                        let peripheral = match adapter.peripheral(&id).await {
                            Ok(p) => p,
                            Err(e) => {
                                error!("could not get info for BTLE peripheral {id:?}: {e:?}");
                                continue;
                            }
                        };

                        let properties = match peripheral.properties().await {
                            Ok(Some(p)) => p,
                            Ok(None) => {
                                error!(
                                    "no properties available for BTLE peripheral {id:?}, ignoring"
                                );
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "could not get properties for BTLE peripheral {id:?}: {e:?}"
                                );
                                continue;
                            }
                        };

                        trace!("services: {:?}", properties.services);
                        // Hideez key seems to lack services on rediscovery?
                        if !properties.services.is_empty()
                            && !properties.services.contains(&FIDO_GATT_SERVICE)
                        {
                            trace!("BTLE peripheral {id:?} is not a FIDO token, skipping");
                            continue;
                        }

                        trace!("device name: {:?}", properties.local_name);
                        recents.insert(id, Instant::now());
                        if let Err(e) = peripheral.connect().await {
                            error!("could not connect: {e:?}");
                        }
                    }

                    CentralEvent::ServicesAdvertisement { id, services } => {
                        // macOS doesn't fire another DeviceDiscovered event if
                        // a device goes away and then comes back.
                        trace!("services advertisement: {id:?} {services:?}");
                        if !services.contains(&FIDO_GATT_SERVICE) {
                            trace!("BTLE peripheral {id:?} is not a FIDO token, skipping");
                            continue;
                        }

                        let peripheral = match adapter.peripheral(&id).await {
                            Ok(p) => p,
                            Err(e) => {
                                error!("could not get info for BTLE peripheral {id:?}: {e:?}");
                                continue;
                            }
                        };

                        if peripheral.is_connected().await? {
                            trace!("ignoring connected peripheral: {id:?}");
                            continue;
                        }

                        if let Some(last_seen) = recents.get(&id) {
                            if last_seen.elapsed() < debounce {
                                trace!("ignoring recently-seen device: {id:?}");
                                recents.insert(id, Instant::now());
                                continue;
                            }

                            recents.remove(&id);
                        }

                        let properties = match peripheral.properties().await {
                            Ok(Some(p)) => p,
                            Ok(None) => {
                                error!(
                                    "no properties available for BTLE peripheral {id:?}, ignoring"
                                );
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "could not get properties for BTLE peripheral {id:?}: {e:?}"
                                );
                                continue;
                            }
                        };

                        trace!("device name: {:?}", properties.local_name);
                        recents.insert(id, Instant::now());
                        if let Err(e) = peripheral.connect().await {
                            error!("could not connect: {e:?}");
                        }
                    }

                    _ => (),
                }
            }

            adapter.stop_scan().await
        });

        Ok(Self { stream })
    }
}

impl Stream for BluetoothDeviceWatcher {
    type Item = TokenEvent<BluetoothToken>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        ReceiverStream::poll_next(Pin::new(&mut Pin::get_mut(self).stream), cx)
    }
}

#[derive(Debug)]
pub struct BluetoothTransport {
    manager: Manager,
}

impl BluetoothTransport {
    /// Creates a new instance of the Bluetooth Low Energy scanner.
    pub async fn new() -> Result<Self, WebauthnCError> {
        Ok(Self {
            manager: Manager::new().await?,
        })
    }
}

#[async_trait]
impl<'b> Transport<'b> for BluetoothTransport {
    type Token = BluetoothToken;

    /// ## Important
    ///
    /// [`tokens()`] is unsupported for [BluetoothTransport], as BTLE
    /// authenticator connections are very short-lived and timing sensitive.
    ///
    /// This method will always return an empty `Vec` of devices.
    ///
    /// Use [`watch()`][] instead.
    ///
    /// [`tokens()`]: BluetoothTransport::tokens
    /// [`watch()`]: BluetoothTransport::watch
    async fn tokens(&self) -> Result<Vec<Self::Token>, WebauthnCError> {
        warn!("tokens() is not supported for Bluetooth devices, use watch()");
        Ok(vec![])
    }

    /// Watches for and connects to nearby Bluetooth Low Energy authenticators.
    ///
    /// ## Note
    ///
    /// Due to the nature of the Bluetooth Low Energy transport,
    /// [BluetoothTransport] immediately emits a
    /// [TokenEvent::EnumerationComplete] event as soon as it starts.
    async fn watch(&self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError> {
        trace!("Scanning for BTLE tokens");
        let stream = BluetoothDeviceWatcher::new(self, Duration::from_secs(10)).await?;
        Ok(Box::pin(stream))
    }
}

#[derive(Debug)]
pub struct BluetoothToken {
    device: Peripheral,
    mtu: usize,
    control_point: Option<Characteristic>,
}

impl BluetoothToken {
    fn new(device: Peripheral) -> Self {
        BluetoothToken {
            device,
            mtu: 0,
            control_point: None,
        }
    }

    /// Gets the current MTU for the authenticator.
    ///
    /// Returns [WebauthnCError::UnexpectedState] if it is out of range.
    #[inline]
    fn checked_mtu(&self) -> Result<usize, WebauthnCError> {
        if !VALID_MTU_RANGE.contains(&self.mtu) {
            Err(WebauthnCError::UnexpectedState)
        } else {
            Ok(self.mtu)
        }
    }

    /// Sends a single [BtleFrame] to the device, without fragmentation.
    async fn send_one(&self, frame: BtleFrame) -> Result<(), WebauthnCError> {
        let d = frame.as_vec(self.checked_mtu()?)?;
        trace!(">>> {}", hex::encode(&d));
        self.device
            .write(
                self.control_point
                    .as_ref()
                    .ok_or(WebauthnCError::UnexpectedState)?,
                &d,
                WriteType::WithResponse,
            )
            .await?;
        Ok(())
    }

    /// Sends a [BtleFrame] to the device, fragmenting the message to fit
    /// within the BTLE MTU.
    async fn send(&self, frame: &BtleFrame) -> Result<(), WebauthnCError> {
        for f in BtleFrameIterator::new(frame, self.checked_mtu()?)? {
            self.send_one(f).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Token for BluetoothToken {
    type Id = PeripheralId;

    async fn transmit_raw<U>(&mut self, cmd: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        // We need to get the notification stream for each command, because
        // otherwise could lose messages while waiting for a response. This
        // provides an asynchronous stream of events as they come in.
        let mut stream = self.device.notifications().await?;

        // In CTAP2 mode, `U2FHID_MSG` is a raw CBOR message.
        let cmd = BtleFrame {
            cmd: U2FHID_MSG,
            len: cmd.len() as u16,
            data: cmd.to_vec(),
        };
        self.send(&cmd).await?;

        // Get a response, checking for keep-alive
        let resp = loop {
            let mut t = 0usize;
            let mut s = 0usize;
            let mut c = Vec::new();

            while let Some(data) = stream.next().await {
                trace!("<<< {}", hex::encode(&data.value));
                if data.uuid != FIDO_STATUS {
                    trace!("Ignoring notification for unknown UUID: {:?}", data.uuid);
                    continue;
                }

                let frame = BtleFrame::try_from(data.value.as_slice())?;
                if frame.cmd >= TYPE_INIT {
                    if t == 0 {
                        // Initial frame contains length
                        t = usize::from(frame.len);
                    } else {
                        error!("Unexpected initial frame");
                        return Err(WebauthnCError::Unknown);
                    }
                } else if t == 0 {
                    error!("Unexpected continuation frame");
                    return Err(WebauthnCError::Unknown);
                }

                s += frame.data.len();
                c.push(frame);

                if s >= t {
                    // We have all the chunks we expected.
                    break;
                }
            }

            if s < t {
                error!("Stream stopped before getting complete message");
                return Err(WebauthnCError::Unknown);
            }

            let f: BtleFrame = c.iter().sum();
            trace!("recv done: {f:?}");
            let resp = Response::try_from(&f)?;
            trace!("Response: {resp:?}");

            if let Response::KeepAlive(r) = resp {
                trace!("waiting for {:?}", r);
                match r {
                    KeepAliveStatus::UserPresenceNeeded => ui.request_touch(),
                    KeepAliveStatus::Processing => ui.processing(),
                    _ => (),
                }
                // TODO: maybe time out at some point
                // thread::sleep(Duration::from_millis(100));
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
        if !self.device.is_connected().await? {
            self.device.connect().await?;
        }

        self.device.discover_services().await?;
        let service = self
            .device
            .services()
            .into_iter()
            .find(|s| s.uuid == FIDO_GATT_SERVICE)
            .ok_or(WebauthnCError::NotSupported)?;

        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ble-protocol-overview
        // 5. Client checks if the fidoServiceRevisionBitfield characteristic is
        // present. If so, the client selects a supported version by writing a
        // value with a single bit set.
        if let Some(c) = service
            .characteristics
            .iter()
            .find(|c| c.uuid == FIDO_SERVICE_REVISION_BITFIELD)
        {
            trace!("Selecting protocol version");
            if let Some(b) = self.device.read(c).await?.first() {
                trace!("Service revision bitfield: {b:#08b}");
                if b & SERVICE_REVISION_CTAP2 == 0 {
                    error!("Device does not support CTAP2, not supported!");
                    return Err(WebauthnCError::NotSupported);
                }

                trace!("Requesting CTAP2");
                self.device
                    .write(c, &[SERVICE_REVISION_CTAP2], WriteType::WithResponse)
                    .await?;
                trace!("Done");
            } else {
                error!("Could not read protocol version");
                return Err(WebauthnCError::MissingRequiredField);
            }
        } else {
            error!("Device does not support CTAP2, not supported!");
            return Err(WebauthnCError::NotSupported);
        }

        // 6. Client reads the fidoControlPointLength characteristic.
        if let Some(c) = service
            .characteristics
            .iter()
            .find(|c| c.uuid == FIDO_CONTROL_POINT_LENGTH)
        {
            let b = self.device.read(c).await?;
            if b.len() < 2 {
                return Err(WebauthnCError::MessageTooShort);
            }
            self.mtu = u16::from_be_bytes(
                b[0..2]
                    .try_into()
                    .map_err(|_| WebauthnCError::MessageTooShort)?,
            ) as usize;
            trace!("Control point length: {}", self.mtu);
            if self.mtu < 20 || self.mtu > 512 {
                error!("Control point length must be between 20 and 512 bytes");
                return Err(WebauthnCError::NotSupported);
            }
        } else {
            error!("No control point length specified!");
            return Err(WebauthnCError::MissingRequiredField);
        }

        // 7. Client registers for notifications on the fidoStatus
        // characteristic.
        if let Some(c) = service
            .characteristics
            .iter()
            .find(|c| c.uuid == FIDO_STATUS)
        {
            self.device.subscribe(c).await?;
        } else {
            error!("No status attribute, cannot get responses to commands!");
            return Err(WebauthnCError::MissingRequiredField);
        }

        // We want to be able to send some messages later.
        if let Some(c) = service
            .characteristics
            .iter()
            .find(|c| c.uuid == FIDO_CONTROL_POINT)
        {
            self.control_point = Some(c.to_owned());
        } else {
            error!("No control point attribute, cannot send commands!");
            return Err(WebauthnCError::MissingRequiredField);
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        if self.device.is_connected().await.unwrap_or_default() {
            self.device.disconnect().await?;
        }
        Ok(())
    }

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Ble
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        self.send_one(BtleFrame {
            cmd: BTLE_CANCEL,
            len: 0,
            data: vec![],
        })
        .await
    }
}

impl Drop for BluetoothToken {
    fn drop(&mut self) {
        trace!("dropping");
        block_on(self.close()).ok();
    }
}

/// Parser for a response [BtleFrame].
///
/// The frame must be complete (ie: all fragments received) before parsing.
impl TryFrom<&BtleFrame> for Response {
    type Error = WebauthnCError;

    fn try_from(f: &BtleFrame) -> Result<Response, WebauthnCError> {
        if !f.complete() {
            error!("cannot parse incomplete frame");
            return Err(WebauthnCError::UnexpectedState);
        }

        let b = &f.data[..];
        Ok(match f.cmd {
            U2FHID_PING => Response::Ping(b.to_vec()),
            BTLE_KEEPALIVE => Response::KeepAlive(KeepAliveStatus::from(b)),
            U2FHID_MSG => CBORResponse::try_from(b).map(Response::Cbor)?,
            U2FHID_ERROR => Response::Error(U2FError::from(b)),
            _ => {
                error!("unknown BTLE command: 0x{:02x}", f.cmd,);
                Response::Unknown
            }
        })
    }
}
