use std::{fmt, mem::size_of, pin::Pin, fs::File, io::Read};

use async_trait::async_trait;
use futures::{stream::BoxStream, Stream};
use tokio::sync::mpsc::{self};

use tokio_stream::wrappers::ReceiverStream;
use tokio_udev::Enumerator;

use crate::{
    error::Result,
    usb::{
        platform::{traits::{USBDevice, USBDeviceInfo, USBDeviceManager, WatchEvent}, descriptors::is_fido_authenticator},
        HidReportBytes, HidSendReportBytes,
    },
};

#[derive(Debug)]
pub struct USBDeviceManagerImpl {}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = String;

    async fn watch_devices(&mut self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>> {
        trace!("watch_devices");
        todo!()
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>> {
        let mut enumerator = Enumerator::new()?;
        enumerator.match_subsystem("hidraw")?;
        let devices = enumerator.scan_devices()?;

        for device in devices {
            // trace!("device: {:?}", device);

            let descriptor_path = device.syspath().join("device").join("report_descriptor");
            trace!("Report descriptor: {descriptor_path:?}");

            let mut file = File::open(descriptor_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            drop(file);
            trace!("raw descriptor: {}", hex::encode(&buf));

            let fido = is_fido_authenticator(&buf);
            trace!(?fido);

        }
        todo!()
    }

    fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[derive(Debug)]
pub struct USBDeviceInfoImpl {}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = String;

    async fn open(self) -> Result<Self::Device> {
        todo!()
    }
}

#[derive(Debug)]
pub struct USBDeviceImpl {}

#[async_trait]
impl USBDevice for USBDeviceImpl {
    type Info = USBDeviceInfoImpl;

    fn get_info(&self) -> &Self::Info {
        todo!()
    }

    async fn read(&mut self) -> Result<HidReportBytes> {
        todo!()
    }

    async fn write(&self, data: HidSendReportBytes) -> Result<()> {
        todo!()
    }
}
