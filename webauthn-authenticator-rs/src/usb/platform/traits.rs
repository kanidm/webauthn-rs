use async_trait::async_trait;
use futures::stream::BoxStream;
use std::fmt::Debug;

use crate::{
    error::WebauthnCError,
    usb::{HidReportBytes, HidSendReportBytes},
};

#[async_trait]
pub trait USBDeviceManager: Sized {
    type Device: USBDevice;
    type DeviceInfo: USBDeviceInfo<Device = Self::Device>;

    fn new() -> Result<Self, WebauthnCError>;

    /// Watches for USB authenticator device connection and disconnection events
    /// indefinitely.
    fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>, WebauthnCError>;

    /// Gets a list of USB authenticators connected right now.
    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>, WebauthnCError>;
}

#[derive(Debug)]
pub enum WatchEvent<T>
where
    T: USBDeviceInfo,
{
    Added(T),
    Removed(T::Id),
    EnumerationComplete,
}

#[async_trait]
pub trait USBDeviceInfo: Debug {
    type Device: USBDevice;
    type Id: Debug;

    async fn open(self) -> Result<Self::Device, WebauthnCError>;
}

#[async_trait]
pub trait USBDevice: Send {
    type Info: USBDeviceInfo<Device = Self>;

    fn get_info(&self) -> &Self::Info;
    async fn read(&mut self) -> Result<HidReportBytes, WebauthnCError>;
    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError>;
}
