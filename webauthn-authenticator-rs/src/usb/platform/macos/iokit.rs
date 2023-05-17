/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use mach2::kern_return::{kern_return_t, KERN_SUCCESS};

use bitflags::bitflags;
use core_foundation::array::*;
use core_foundation::base::*;
use core_foundation::date::CFAbsoluteTimeGetCurrent;
use core_foundation::dictionary::*;
use core_foundation::number::*;
use core_foundation::runloop::*;
use core_foundation::set::{CFSet, CFSetGetValues, CFSetRef};
use core_foundation::string::*;
use std::error::Error;
use std::ffi::{c_char, CStr};
use std::fmt::{self, Debug, Display};
use std::ops::Deref;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::time::Duration;

use crate::{
    error::WebauthnCError,
    usb::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID},
};

type IOOptionBits = u32;

#[repr(C)]
pub struct IOReturn(kern_return_t);

extern "C" {
    fn mach_error_string(error_value: kern_return_t) -> *const c_char;
}

impl IOReturn {
    const kIOReturnSuccess: kern_return_t = KERN_SUCCESS as c_int;

    pub fn message(&self) -> Option<&'static str> {
        let s = unsafe {
            let p = mach_error_string(self.0);
            if p.is_null() {
                return None;
            }
            CStr::from_ptr(p)
        };

        s.to_str().ok()
    }

    pub fn into_result(self) -> Result<(), Self> {
        match self.0 {
            Self::kIOReturnSuccess => Ok(()),
            _ => Err(self),
        }
    }
}

impl From<IOReturn> for WebauthnCError {
    fn from(e: IOReturn) -> Self {
        WebauthnCError::IoError(format!("{e:?}"))
    }
}

impl Error for IOReturn {}

impl Display for IOReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)?;
        if let Some(msg) = self.message() {
            write!(f, ": {msg}")?;
        }
        Ok(())
    }
}

impl Debug for IOReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IOReturn")
            .field("id", &format!("0x{:x}", self.0))
            .field("message", &self.message().unwrap_or_default())
            .finish()
    }
}

pub type IOHIDDeviceCallback = extern "C" fn(
    context: *mut c_void,
    result: IOReturn,
    sender: *mut c_void,
    device: IOHIDDeviceRef,
);

pub type IOHIDReportCallback = extern "C" fn(
    context: *mut c_void,
    result: IOReturn,
    sender: IOHIDDeviceRef,
    report_type: IOHIDReportType,
    report_id: u32,
    report: *mut u8,
    report_len: CFIndex,
);

bitflags! {
    #[derive(Default)]
    #[repr(C)]
    pub struct IOHIDManagerOptions: u32 {
        const USE_PERSISTENT_PROPERTIES = 0x01;
        const DO_NOT_LOAD_PROPERTIES = 0x02;
        const DO_NOT_SAVE_PROPERTIES = 0x04;
        const INDEPENDENT_DEVICES = 0x08;
    }
}

#[repr(u32)]
pub enum IOHIDReportType {
    Input = 0,
    Output,
    Feature,
    Count,
}

#[repr(C)]
pub struct __IOHIDManager(c_void);
pub type IOHIDManagerRef = *mut __IOHIDManager;
declare_TCFType!(IOHIDManager, IOHIDManagerRef);
impl_TCFType!(IOHIDManager, IOHIDManagerRef, IOHIDManagerGetTypeID);
impl_CFTypeDescription!(IOHIDManager);

unsafe impl Send for IOHIDManager {}
unsafe impl Sync for IOHIDManager {}

#[repr(C)]
pub struct __IOHIDDevice(c_void);
pub type IOHIDDeviceRef = *mut __IOHIDDevice;
declare_TCFType!(IOHIDDevice, IOHIDDeviceRef);
impl_TCFType!(IOHIDDevice, IOHIDDeviceRef, IOHIDDeviceGetTypeID);
impl_CFTypeDescription!(IOHIDDevice);

unsafe impl Send for IOHIDDevice {}
unsafe impl Sync for IOHIDDevice {}

/// `Sendable` wraps arbitrary Core Foundation types to mark them as [`Send`]
/// (thread-safe).
///
/// `core-foundation-rs` marks very few types as `Send`, even though
/// [Apple's documentation indicates immutable Core Foundation types are
/// generally thread-safe][0].
///
/// Once this is [addressed upstream][1], this will become unnecessary.
///
/// ## Safety
///
/// This is only safe where `T` is a thread-safe type.
///
/// [0]: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/ThreadSafetySummary/ThreadSafetySummary.html#//apple_ref/doc/uid/10000057i-CH12-SW9
/// [1]: https://github.com/servo/core-foundation-rs/issues/550
pub struct Sendable<T: TCFType>(pub T);

unsafe impl<T: TCFType> Send for Sendable<T> {}

impl<T: TCFType> Deref for Sendable<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: TCFType + Debug> Debug for Sendable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sendable").field(&self.0).finish()
    }
}

pub struct CFRunLoopTimerHelper {
    timer: CFRunLoopTimer,
}

impl CFRunLoopTimerHelper {
    pub fn new(callback: CFRunLoopTimerCallBack, info: *mut c_void, delay: Duration) -> Self {
        // CFRunLoopTimerCreate copies the CFRunLoopTimerContext, so there is no
        // need to persist it beyond that function call.
        let mut context = CFRunLoopTimerContext {
            version: 0,
            info,
            retain: None,
            release: None,
            copyDescription: None,
        };

        let timer = unsafe {
            let fire_date = CFAbsoluteTimeGetCurrent() + delay.as_secs_f64();
            CFRunLoopTimer::new(fire_date, 0., 0, 0, callback, &mut context)
        };

        Self { timer }
    }

    pub fn add_to_current_runloop(&self) {
        unsafe {
            CFRunLoop::get_current().add_timer(&self.timer, kCFRunLoopDefaultMode);
        }
    }
}

pub struct CFRunLoopEntryObserver {
    observer: CFRunLoopObserver,
}

impl CFRunLoopEntryObserver {
    pub fn new(callback: CFRunLoopObserverCallBack, info: *mut c_void) -> Self {
        // CFRunLoopObserverCreate copies the CFRunLoopObserverContext, so
        // there is no need to persist it beyond that function call.
        let mut context = CFRunLoopObserverContext {
            version: 0,
            info,
            retain: None,
            release: None,
            copyDescription: None,
        };

        let observer = unsafe {
            CFRunLoopObserver::wrap_under_create_rule(CFRunLoopObserverCreate(
                kCFAllocatorDefault,
                kCFRunLoopEntry,
                false as Boolean,
                0,
                callback,
                &mut context,
            ))
        };

        Self { observer }
    }

    pub fn add_to_current_runloop(&self) {
        unsafe {
            CFRunLoop::get_current().add_observer(&self.observer, kCFRunLoopDefaultMode);
        }
    }
}

pub struct IOHIDDeviceMatcher {
    pub dict: CFDictionary<CFString, CFNumber>,
}

impl IOHIDDeviceMatcher {
    pub fn new() -> Self {
        let dict = CFDictionary::<CFString, CFNumber>::from_CFType_pairs(&[
            (
                CFString::from_static_string("DeviceUsage"),
                CFNumber::from(i32::from(FIDO_USAGE_U2FHID)),
            ),
            (
                CFString::from_static_string("DeviceUsagePage"),
                CFNumber::from(i32::from(FIDO_USAGE_PAGE)),
            ),
        ]);
        Self { dict }
    }
}

impl IOHIDManager {
    pub fn create(options: IOHIDManagerOptions) -> Self {
        unsafe { TCFType::wrap_under_create_rule(IOHIDManagerCreate(kCFAllocatorDefault, options)) }
    }

    pub fn copy_devices(&self) -> Vec<IOHIDDevice> {
        unsafe {
            let s: CFSet<c_void> =
                CFSet::wrap_under_get_rule(IOHIDManagerCopyDevices(self.as_concrete_TypeRef()));
            let mut refs: Vec<*const c_void> = Vec::with_capacity(s.len());

            CFSetGetValues(s.as_concrete_TypeRef(), refs.as_mut_ptr());
            refs.set_len(s.len());

            refs.into_iter()
                .map(|ptr| IOHIDDeviceRef::from_void_ptr(ptr).into())
                .collect()
        }
    }

    pub fn set_device_matching(&self, matching: Option<&IOHIDDeviceMatcher>) {
        unsafe {
            IOHIDManagerSetDeviceMatching(
                self.as_concrete_TypeRef(),
                matching.map_or(ptr::null(), |m| m.dict.as_concrete_TypeRef()),
            )
        }
    }

    pub fn register_device_matching_callback(
        &self,
        callback: IOHIDDeviceCallback,
        context: *const c_void,
    ) {
        unsafe {
            IOHIDManagerRegisterDeviceMatchingCallback(
                self.as_concrete_TypeRef(),
                callback,
                context,
            )
        }
    }

    pub fn register_device_removal_callback(
        &self,
        callback: IOHIDDeviceCallback,
        context: *const c_void,
    ) {
        unsafe {
            IOHIDManagerRegisterDeviceRemovalCallback(self.as_concrete_TypeRef(), callback, context)
        }
    }

    pub fn open(&self, options: IOHIDManagerOptions) -> Result<(), IOReturn> {
        unsafe { IOHIDManagerOpen(self.as_concrete_TypeRef(), options) }.into_result()
    }

    pub fn close(&self, options: IOHIDManagerOptions) -> Result<(), IOReturn> {
        unsafe { IOHIDManagerClose(self.as_concrete_TypeRef(), options) }.into_result()
    }

    pub fn schedule_with_run_loop(&self, runloop: &CFRunLoop) {
        unsafe {
            IOHIDManagerScheduleWithRunLoop(
                self.as_concrete_TypeRef(),
                runloop.as_concrete_TypeRef(),
                kCFRunLoopDefaultMode,
            );
        }
    }

    pub fn unschedule_from_run_loop(&self, runloop: &CFRunLoop) {
        unsafe {
            IOHIDManagerUnscheduleFromRunLoop(
                self.as_concrete_TypeRef(),
                runloop.as_concrete_TypeRef(),
                kCFRunLoopDefaultMode,
            )
        }
    }
}

impl IOHIDDevice {
    pub fn set_report(
        &self,
        reportType: IOHIDReportType,
        reportID: CFIndex,
        report: &[u8],
    ) -> Result<(), IOReturn> {
        unsafe {
            IOHIDDeviceSetReport(
                self.as_concrete_TypeRef(),
                reportType,
                reportID,
                report.as_ptr(),
                report.len().to_CFIndex(),
            )
        }
        .into_result()
    }

    pub fn register_input_report_callback(
        &self,
        report: *mut u8,
        reportLength: usize,
        callback: IOHIDReportCallback,
        context: *const c_void,
    ) {
        unsafe {
            IOHIDDeviceRegisterInputReportCallback(
                self.as_concrete_TypeRef(),
                report,
                reportLength.to_CFIndex(),
                callback,
                context,
            );
        }
    }

    pub fn schedule_with_run_loop(&self, runloop: &CFRunLoop) {
        unsafe {
            IOHIDDeviceScheduleWithRunLoop(
                self.as_concrete_TypeRef(),
                runloop.as_concrete_TypeRef(),
                kCFRunLoopDefaultMode,
            );
        }
    }

    pub fn unschedule_from_run_loop(&self, runloop: &CFRunLoop) {
        unsafe {
            IOHIDDeviceUnscheduleFromRunLoop(
                self.as_concrete_TypeRef(),
                runloop.as_concrete_TypeRef(),
                kCFRunLoopDefaultMode,
            );
        }
    }

    pub fn close(&self, options: IOOptionBits) -> Result<(), IOReturn> {
        unsafe { IOHIDDeviceClose(self.as_concrete_TypeRef(), options) }.into_result()
    }

    pub fn open(&self, options: IOOptionBits) -> Result<(), IOReturn> {
        unsafe { IOHIDDeviceOpen(self.as_concrete_TypeRef(), options) }.into_result()
    }
}

impl From<IOHIDDeviceRef> for IOHIDDevice {
    fn from(r: IOHIDDeviceRef) -> Self {
        unsafe { TCFType::wrap_under_get_rule(r) }
    }
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    // IOHIDManager
    fn IOHIDManagerGetTypeID() -> CFTypeID;

    fn IOHIDManagerCreate(
        allocator: CFAllocatorRef,
        options: IOHIDManagerOptions,
    ) -> IOHIDManagerRef;
    fn IOHIDManagerCopyDevices(manager: IOHIDManagerRef) -> CFSetRef;
    fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFDictionaryRef);
    fn IOHIDManagerRegisterDeviceMatchingCallback(
        manager: IOHIDManagerRef,
        callback: IOHIDDeviceCallback,
        context: *const c_void,
    );
    fn IOHIDManagerRegisterDeviceRemovalCallback(
        manager: IOHIDManagerRef,
        callback: IOHIDDeviceCallback,
        context: *const c_void,
    );
    fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    fn IOHIDManagerClose(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    fn IOHIDManagerScheduleWithRunLoop(
        manager: IOHIDManagerRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );
    fn IOHIDManagerUnscheduleFromRunLoop(
        manager: IOHIDManagerRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );

    // IOHIDDevice
    fn IOHIDDeviceGetTypeID() -> CFTypeID;
    fn IOHIDDeviceSetReport(
        device: IOHIDDeviceRef,
        reportType: IOHIDReportType,
        reportID: CFIndex,
        report: *const u8,
        reportLength: CFIndex,
    ) -> IOReturn;
    fn IOHIDDeviceRegisterInputReportCallback(
        device: IOHIDDeviceRef,
        report: *mut u8,
        reportLength: CFIndex,
        callback: IOHIDReportCallback,
        context: *const c_void,
    );
    fn IOHIDDeviceScheduleWithRunLoop(
        device: IOHIDDeviceRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );
    fn IOHIDDeviceUnscheduleFromRunLoop(
        device: IOHIDDeviceRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );
    fn IOHIDDeviceClose(device: IOHIDDeviceRef, options: IOOptionBits) -> IOReturn;
    fn IOHIDDeviceOpen(device: IOHIDDeviceRef, options: IOOptionBits) -> IOReturn;
}

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::raw::c_void;
    use std::sync::mpsc::{channel, Sender};
    use std::thread;

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        let tx: &Sender<Sendable<CFRunLoop>> = unsafe { &*(context as *mut _) };

        // Send the current runloop to the receiver to unblock it.
        let _ = tx.send(Sendable(CFRunLoop::get_current()));
    }

    #[test]
    fn test_sendable_runloop() {
        let (tx, rx) = channel();

        let thread = thread::spawn(move || {
            // Send the runloop to the owning thread.
            let context = &tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(observe, context);
            obs.add_to_current_runloop();

            unsafe {
                // We need some source for the runloop to run.
                let runloop = CFRunLoop::get_current();
                let manager = IOHIDManager::create(IOHIDManagerOptions::empty());
                manager.schedule_with_run_loop(&runloop);

                // Set an explicit device filter so that we don't need "Input Monitoring" permissions.
                let matcher = IOHIDDeviceMatcher::new();
                manager.set_device_matching(Some(&matcher));
                manager.open(IOHIDManagerOptions::empty()).unwrap();

                // This will run until `CFRunLoopStop()` is called.
                CFRunLoopRun();
                manager.close(IOHIDManagerOptions::empty()).unwrap();
            }
        });

        // Block until we enter the CFRunLoop.
        let runloop: Sendable<CFRunLoop> = rx.recv().expect("failed to receive runloop");

        // Stop the runloop.
        runloop.stop();

        // Stop the thread.
        thread.join().expect("failed to join the thread");

        // Try to stop the runloop again (without crashing).
        runloop.stop();
    }
}
