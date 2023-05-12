use std::{fmt, mem::size_of};

use async_trait::async_trait;
use tokio::sync::mpsc;

use windows::{
    core::HRESULT,
    Devices::{
        Enumeration::DeviceInformation,
        HumanInterfaceDevice::{HidDevice, HidInputReport, HidInputReportReceivedEventArgs},
    },
    Foundation::{EventRegistrationToken, TypedEventHandler},
    Storage::{
        FileAccessMode,
        Streams::{DataReader, DataWriter},
    },
    Win32::Foundation::{ERROR_BAD_ARGUMENTS, ERROR_HANDLES_CLOSED},
};

use crate::{
    error::WebauthnCError,
    usb::{
        platform::traits::{PlatformUSBDevice, PlatformUSBDeviceInfo, PlatformUSBDeviceManager},
        HidReportBytes, HidSendReportBytes, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID,
    },
};

#[derive(Debug)]
pub struct WindowsUSBDeviceManager {}

#[async_trait]
impl PlatformUSBDeviceManager for WindowsUSBDeviceManager {
    type Device = WindowsUSBDevice;
    type DeviceInfo = WindowsUSBDeviceInfo;

    async fn get_devices(&self) -> Vec<Self::DeviceInfo> {
        let selector = HidDevice::GetDeviceSelector(FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID).unwrap();
        let ret = DeviceInformation::FindAllAsyncAqsFilter(&selector)
            .unwrap()
            .await;

        let ret = ret.expect("async returned error");

        ret.into_iter()
            .map(|info| WindowsUSBDeviceInfo { info })
            .collect()
    }

    fn new() -> Result<Self, WebauthnCError> {
        Ok(Self {})
    }
}

pub struct WindowsUSBDeviceInfo {
    info: DeviceInformation,
}

#[async_trait]
impl PlatformUSBDeviceInfo for WindowsUSBDeviceInfo {
    type Device = WindowsUSBDevice;

    async fn open(&self) -> Result<Self::Device, WebauthnCError> {
        WindowsUSBDevice::new(&self).await
    }
}

impl fmt::Debug for WindowsUSBDeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsUSBDeviceInfo")
            .field("id", &self.info.Id().unwrap_or_default().to_string())
            .field("name", &self.info.Name().unwrap_or_default().to_string())
            .finish()
    }
}

#[derive(Debug)]
pub struct WindowsUSBDevice {
    device: HidDevice,
    listener_token: EventRegistrationToken,
    rx: mpsc::Receiver<HidInputReport>,
}

impl Drop for WindowsUSBDevice {
    fn drop(&mut self) {
        self.device
            .RemoveInputReportReceived(self.listener_token)
            .unwrap();
    }
}

impl WindowsUSBDevice {
    async fn new(info: &WindowsUSBDeviceInfo) -> Result<Self, WebauthnCError> {
        trace!("Opening device: {info:?}");
        let device_id = info.info.Id().map_err(|e| {
            error!("Unable to get device ID: {e}");
            WebauthnCError::Internal
        })?;

        let device = HidDevice::FromIdAsync(&device_id, FileAccessMode::ReadWrite)
            .unwrap()
            .await;
        let device = device.unwrap();

        // HidDevice returns data using the InputReportReceived event. Stash the
        // data into a channel to pick up later.
        let (tx, rx) = mpsc::channel(100);
        let listener_token = device
            .InputReportReceived(&TypedEventHandler::<
                HidDevice,
                HidInputReportReceivedEventArgs,
            >::new(move |_, args| {
                let args = args.as_ref().ok_or::<HRESULT>(ERROR_BAD_ARGUMENTS.into())?;
                let report = args.Report()?;
                tx.blocking_send(report)
                    .map_err(|_| ERROR_HANDLES_CLOSED.into())
            }))
            .unwrap();

        let o = WindowsUSBDevice {
            device,
            listener_token,
            rx,
        };
        Ok(o)
    }
}

#[async_trait]
impl PlatformUSBDevice for WindowsUSBDevice {
    async fn read(&mut self) -> Result<HidReportBytes, WebauthnCError> {
        let ret = self.rx.recv().await;
        // let ret = self.device.GetInputReportByIdAsync(0).unwrap().await;
        let ret = ret.unwrap();
        let buf = ret.Data().unwrap();
        let len = buf.Length().unwrap() as usize;
        println!("Read buffer length: {len}");
        let dr = DataReader::FromBuffer(&buf).expect("DataReader::FromBuffer");

        let mut o = [0; size_of::<HidReportBytes>()];
        // Drop the leading report ID byte
        dr.ReadByte().ok();
        dr.ReadBytes(&mut o).expect("ReadBytes");

        Ok(o)
    }

    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError> {
        let report = self.device.CreateOutputReportById(data[0] as u16).unwrap();
        let dw = DataWriter::new().unwrap();
        dw.WriteBytes(&data[..]).unwrap();
        report
            .SetData(&dw.DetachBuffer().expect("DetachBuffer"))
            .expect("SetData");
        let ret = self
            .device
            .SendOutputReportAsync(&report)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(ret as usize, size_of::<HidSendReportBytes>());
        Ok(())
    }
}
