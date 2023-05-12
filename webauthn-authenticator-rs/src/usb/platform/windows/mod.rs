/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// use std::fs::{File, OpenOptions};
// use std::io::{Read, Result as IOResult, Write};
use std::mem::size_of;
// use std::os::windows::io::AsRawHandle;
// use std::os::windows::prelude::{AsHandle, RawHandle};

use async_trait::async_trait;
use windows::{
    Devices::{Enumeration::DeviceInformation, HumanInterfaceDevice::HidDevice},
    Storage::{
        FileAccessMode,
        Streams::{DataReader, DataWriter},
    },
    // Win32::{
    //     Devices::HumanInterfaceDevice::{
    //         HidD_FreePreparsedData, HidD_GetPreparsedData, HidP_GetCaps, HIDP_CAPS,
    //     },
    //     Foundation::HANDLE,
    // },
};

use crate::usb::{HidReportBytes, HidSendReportBytes, HID_RPT_SIZE};
use crate::{
    error::WebauthnCError,
    usb::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID, HID_RPT_SEND_SIZE},
};

use super::traits::{PlatformUSBDevice, PlatformUSBDeviceInfo, PlatformUSBDeviceManager};

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

#[derive(Debug)]
pub struct WindowsUSBDeviceInfo {
    info: DeviceInformation,
}

#[async_trait]
impl PlatformUSBDeviceInfo for WindowsUSBDeviceInfo {
    type Device = WindowsUSBDevice;

    async fn open(&self) -> Result<Self::Device, WebauthnCError> {
        let device_id = self.info.Id().unwrap();
        println!("Opening device: {device_id}, {}", self.info.Name().unwrap());

        let device = HidDevice::FromIdAsync(&device_id, FileAccessMode::ReadWrite)
            .unwrap()
            .await;
        let device = device.unwrap();

        Ok(WindowsUSBDevice { device })
    }
}

#[derive(Debug)]
pub struct WindowsUSBDevice {
    device: HidDevice,
}

impl WindowsUSBDevice {
    // pub fn new(path: String) -> IOResult<Self> {
    //     let file = OpenOptions::new().read(true).write(true).open(&path)?;
    //     let caps = Self::get_caps(file.as_raw_handle());

    //     Ok(Self { path, file, caps })
    // }

    // fn get_caps(handle: RawHandle) -> Option<HIDP_CAPS> {
    //     let handle = HANDLE(handle as isize);
    //     if handle.is_invalid() {
    //         return None;
    //     }

    //     let preparseddata = std::ptr::null_mut();
    //     let r = unsafe { HidD_GetPreparsedData(handle, preparseddata) };

    //     if !r.as_bool() || preparseddata.is_null() {
    //         return None;
    //     }

    //     let mut capabilities = std::mem::MaybeUninit::<HIDP_CAPS>::uninit();
    //     unsafe {
    //         let r = HidP_GetCaps(*preparseddata, capabilities.as_mut_ptr());
    //         HidD_FreePreparsedData(*preparseddata);

    //         if r.is_err() {
    //             return None;
    //         }

    //         return Some(capabilities.assume_init());
    //     }
    // }
}

#[async_trait]
impl PlatformUSBDevice for WindowsUSBDevice {
    async fn read(&self) -> Result<HidReportBytes, WebauthnCError> {
        let ret = self.device.GetInputReportByIdAsync(0).unwrap().await;
        let ret = ret.unwrap();
        let buf = ret.Data().unwrap();
        let len = buf.Length().unwrap() as usize;
        println!("Read buffer length: {len}");
        let dr = DataReader::FromBuffer(&buf).expect("DataReader::FromBuffer");

        let mut o = [0; size_of::<HidSendReportBytes>()];
        dr.ReadBytes(&mut o[..len]).expect("ReadBytes");
        println!("Read bytes: {}", hex::encode(&o[..len]));
        let mut o2 = [0; size_of::<HidReportBytes>()];
        o2.copy_from_slice(&o[1..]);

        Ok(o2)
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

// impl Read for WindowsUSBDevice {
//     fn read(&mut self, bytes: &mut [u8]) -> IOResult<usize> {
//         // Windows always includes the report ID.
//         let mut input = [0; HID_RPT_SEND_SIZE];
//         self.device.GetInputReportByIdAsync(0);

//         let _ = self.file.read(&mut input)?;
//         bytes.clone_from_slice(&input[1..]);
//         Ok(bytes.len() as usize)
//     }
// }

// impl Write for WindowsUSBDevice {
//     fn write(&mut self, bytes: &[u8]) -> IOResult<usize> {
//         self.file.write(bytes)
//     }

//     fn flush(&mut self) -> IOResult<()> {
//         self.file.flush()
//     }
// }
