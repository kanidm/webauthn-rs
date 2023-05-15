/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use async_trait::async_trait;
use core_foundation::{
    base::{kCFAllocatorDefault, CFRelease, TCFType},
    mach_port::CFIndex,
    runloop::{kCFRunLoopDefaultMode, CFRunLoopGetCurrent},
};
use futures::stream::BoxStream;
use libc::c_void;
use std::{fmt, mem::size_of, pin::Pin, slice::from_raw_parts};
use tokio::sync::mpsc;

// mod device;
// pub mod transaction;

mod iokit;
// mod monitor;

use self::iokit::{
    kIOHIDManagerOptionNone, kIOHIDReportTypeOutput, IOHIDDevice, IOHIDDeviceMatcher,
    IOHIDDeviceRef, IOHIDDeviceSetReport, IOHIDManager, IOHIDManagerCreate, IOHIDManagerRef,
    IOHIDManagerSetDeviceMatching, IOHIDReportType, IOReturn,
};

use crate::{
    error::WebauthnCError,
    usb::{
        platform::{
            os::iokit::{
                kIOReturnSuccess, IOHIDDeviceOpen, IOHIDDeviceRegisterInputReportCallback,
                IOHIDDeviceScheduleWithRunLoop,
            },
            traits::*,
        },
        HidReportBytes, HidSendReportBytes,
    },
};

pub struct USBDeviceManagerImpl {
    manager: IOHIDManager,
    _matcher: IOHIDDeviceMatcher,
}

impl fmt::Debug for USBDeviceManagerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBDeviceManagerImpl")
            .field("manager", &self.manager)
            .finish()
    }
}

unsafe impl Send for USBDeviceManagerImpl {}
unsafe impl Sync for USBDeviceManagerImpl {}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = IOHIDDevice;

    fn new() -> Result<Self, WebauthnCError> {
        let manager = unsafe { IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone) };

        // Match FIDO devices only.
        let _matcher = IOHIDDeviceMatcher::new();
        unsafe { IOHIDManagerSetDeviceMatching(manager, _matcher.dict.as_concrete_TypeRef()) };

        Ok(Self { manager, _matcher })
    }

    fn watch_devices(&mut self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>, WebauthnCError> {
        let mut matcher = Box::pin(MacDeviceMatcher {});
        let context = unsafe {
            let matcher_ref = Pin::as_mut(&mut matcher);
            Pin::get_unchecked_mut(matcher_ref) as *mut MacDeviceMatcher as *mut c_void
        };

        todo!()
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>, WebauthnCError> {
        todo!()
    }
}

// impl Drop for USBDeviceManagerImpl {
//     fn drop(&mut self) {
//         unsafe { CFRelease(self.manager.0 as *mut c_void) };
//     }
// }

struct MacDeviceMatcher {}

impl MacDeviceMatcher {
    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        let this = unsafe { &mut *(context as *mut Self) };
        // let _ = this
        //     .selector_sender
        //     .send(DeviceSelectorEvent::DevicesAdded(vec![device_ref]));
        // let selector_sender = this.selector_sender.clone();
        // let status_sender = this.status_sender.clone();
        // let (tx, rx) = channel();
        // let f = &this.new_device_cb;

        // // Create a new per-device runloop.
        // let runloop = RunLoop::new(move |alive| {
        //     // Ensure that the runloop is still alive.
        //     if alive() {
        //         f((device_ref, rx), selector_sender, status_sender, alive);
        //     }
        // });

        // if let Ok(runloop) = runloop {
        //     this.map.insert(device_ref, DeviceData { tx, runloop });
        // }
        todo!()
    }

    extern "C" fn on_device_removal(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        let this = unsafe { &mut *(context as *mut Self) };
        // this.remove_device(device_ref);
        todo!()
    }
}

pub struct USBDeviceInfoImpl {
    device: IOHIDDevice,
}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = IOHIDDevice;

    async fn open(self) -> Result<Self::Device, WebauthnCError> {
        USBDeviceImpl::new(self).await
    }
}

impl fmt::Debug for USBDeviceInfoImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacOSUSBDeviceInfo")
            // .field("id", &self.info.Id().unwrap_or_default().to_string())
            // .field("name", &self.info.Name().unwrap_or_default().to_string())
            .finish()
    }
}

#[derive(Debug)]
pub struct USBDeviceImpl {
    info: USBDeviceInfoImpl,
    tx: mpsc::Sender<HidReportBytes>,
    rx: mpsc::Receiver<HidReportBytes>,
    buf: Pin<Box<HidReportBytes>>,
}

impl USBDeviceImpl {
    async fn new(info: USBDeviceInfoImpl) -> Result<Self, WebauthnCError> {
        trace!("Opening device: {info:?}");

        let buf: Pin<Box<HidReportBytes>> = Box::pin([0; size_of::<HidReportBytes>()]);
        let (tx, rx) = mpsc::channel(100);

        let mut d = Self { info, tx, rx, buf };

        let context = (&mut d) as *mut Self as *mut c_void;

        unsafe {
            let r = IOHIDDeviceRegisterInputReportCallback(
                d.info.device,
                d.buf.as_mut_ptr(),
                d.buf.len().try_into().unwrap(),
                Self::on_input_report,
                context,
            );
            if r != kIOReturnSuccess {
                error!("IOHIDDeviceRegisterInputReportCallback return error: {r}");
                return Err(WebauthnCError::Internal);
            }

            IOHIDDeviceScheduleWithRunLoop(
                d.info.device,
                CFRunLoopGetCurrent(),
                kCFRunLoopDefaultMode,
            );

            let r = IOHIDDeviceOpen(d.info.device, 0);
            if r != kIOReturnSuccess {
                error!("IOHIDDeviceOpen return error: {r}");
                return Err(WebauthnCError::Internal);
            }
        }

        Ok(d)
    }

    extern "C" fn on_input_report(
        context: *mut c_void,
        _: IOReturn,
        _: IOHIDDeviceRef,
        _: IOHIDReportType,
        _: u32,
        report: *mut u8,
        report_len: CFIndex,
    ) {
        let this = unsafe { &mut *(context as *mut Self) };
        println!("on_input_report: len = {report_len}");
        let src_data = unsafe { from_raw_parts(report, report_len as usize) };
        let mut data: HidReportBytes = [0; size_of::<HidReportBytes>()];
        data.copy_from_slice(src_data);
        this.tx.blocking_send(data);
    }
}

#[async_trait]
impl USBDevice for USBDeviceImpl {
    type Info = USBDeviceInfoImpl;

    fn get_info(&self) -> &Self::Info {
        &self.info
    }

    async fn read(&mut self) -> Result<HidReportBytes, WebauthnCError> {
        let ret = self.rx.recv().await;
        ret.ok_or(WebauthnCError::Closed)
    }

    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError> {
        let report_id = data[0];
        let data = &data[if report_id == 0 { 1 } else { 0 }..];
        let r = unsafe {
            IOHIDDeviceSetReport(
                self.device,
                kIOHIDReportTypeOutput,
                report_id.try_into().unwrap(),
                data.as_ptr(),
                data.len() as CFIndex,
            )
        };

        if r != kIOReturnSuccess {
            error!("IOHIDDeviceSetReport return error: {r}");
            return Err(WebauthnCError::ApduTransmission);
        }

        Ok(())
    }
}
