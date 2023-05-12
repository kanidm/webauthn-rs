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

    fn watch_devices<'a>(&'a self) -> Result<BoxStream<'a, WatchEvent<Self::DeviceInfo>>, WebauthnCError>;

    async fn get_devices(&self) -> Vec<Self::DeviceInfo>;
    fn new() -> Result<Self, WebauthnCError>;
}

#[derive(Debug)]
pub enum WatchEvent<T>
where
    T: USBDeviceInfo,
{
    Added(T),
    Removed(T::Id),
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
