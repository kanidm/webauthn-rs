use async_trait::async_trait;

use crate::{error::WebauthnCError, usb::{HidReportBytes, HidSendReportBytes}};

#[async_trait]
pub trait PlatformUSBDeviceManager: Sized {
    type Device: PlatformUSBDevice;
    type DeviceInfo: PlatformUSBDeviceInfo<Device = Self::Device>;

    async fn get_devices(&self) -> Vec<Self::DeviceInfo>;
    fn new() -> Result<Self, WebauthnCError>;
}

#[async_trait]
pub trait PlatformUSBDeviceInfo {
    type Device: PlatformUSBDevice;

    async fn open(&self) -> Result<Self::Device, WebauthnCError>;
}

#[async_trait]
pub trait PlatformUSBDevice: Send {
    async fn read(&self) -> Result<HidReportBytes, WebauthnCError>;
    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError>;
}
