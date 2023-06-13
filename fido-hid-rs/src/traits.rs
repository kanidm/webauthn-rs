use async_trait::async_trait;
use futures::stream::BoxStream;
use std::fmt::Debug;

use crate::{HidReportBytes, HidSendReportBytes, Result};

/// Platform-specific USB device manager.
#[async_trait]
pub trait USBDeviceManager: Sized {
    /// The type used for USB device connections on this platform.
    type Device: USBDevice;
    /// The type used for USB device information produced on this platform.
    type DeviceInfo: USBDeviceInfo<Id = Self::DeviceId>;
    /// The type used for USB device IDs on this platform.
    type DeviceId: Debug;

    /// Instantiates a new [USBDeviceManager] for this platform.
    async fn new() -> Result<Self>;

    /// Watches for USB authenticator device connection and disconnection events
    /// until the resulting stream is dropped.
    ///
    /// This method fires [`WatchEvent::Added`] events for any USB devices
    /// *already* connected, followed by [`WatchEvent::EnumerationComplete`].
    async fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>>;

    /// Gets a list of currently-connected USB authenticators.
    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>>;
}

#[derive(Clone, Debug)]
pub enum WatchEvent<T>
where
    T: USBDeviceInfo,
{
    /// A new device was connected.
    Added(T),
    /// An existing device was disconnected.
    Removed(T::Id),
    /// Initial enumeration of existing devices completed.
    EnumerationComplete,
}

/// Platform-specific USB device info structure.
#[async_trait]
pub trait USBDeviceInfo: Clone + Debug + Send {
    /// The type used for USB device connections on this platform.
    type Device: USBDevice;

    /// The type used for USB device identifiers on this platform.
    type Id: Clone + Debug + Send;

    /// Opens a connection to this USB device.
    async fn open(self) -> Result<Self::Device>;
}

/// Platform-specific USB device connection structure.
#[async_trait]
pub trait USBDevice: Send {
    /// The type used for USB device information on this platform.
    type Info: USBDeviceInfo<Device = Self>;

    /// Gets the device info used to create this connection.
    fn get_info(&self) -> &Self::Info;

    /// Read some bytes from the FIDO device's HID input report descriptor.
    async fn read(&mut self) -> Result<HidReportBytes>;

    /// Write some bytes to the FIDO device's HID output report descriptor.
    async fn write(&mut self, data: HidSendReportBytes) -> Result<()>;
}
