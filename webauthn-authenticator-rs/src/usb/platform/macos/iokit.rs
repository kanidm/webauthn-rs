/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use mach2::kern_return::{kern_return_t, KERN_SUCCESS};

use core_foundation::array::*;
use core_foundation::base::*;
use core_foundation::dictionary::*;
use core_foundation::number::*;
use core_foundation::runloop::*;
use core_foundation::string::*;
use std::fmt;
use std::ops::Deref;
use std::os::raw::{c_int, c_void};

use crate::usb::FIDO_USAGE_PAGE;
use crate::usb::FIDO_USAGE_U2FHID;

type IOOptionBits = u32;

pub type IOReturn = kern_return_t;

pub type IOHIDManagerOptions = IOOptionBits;

pub type IOHIDDeviceCallback = extern "C" fn(
    context: *mut c_void,
    result: IOReturn,
    sender: *mut c_void,
    device: IOHIDDeviceRef,
);

pub type IOHIDReportType = IOOptionBits;
pub type IOHIDReportCallback = extern "C" fn(
    context: *mut c_void,
    result: IOReturn,
    sender: IOHIDDeviceRef,
    report_type: IOHIDReportType,
    report_id: u32,
    report: *mut u8,
    report_len: CFIndex,
);

pub const kIOHIDManagerOptionNone: IOHIDManagerOptions = 0;

pub const kIOHIDReportTypeOutput: IOHIDReportType = 1;

pub const kIOReturnSuccess: IOReturn = KERN_SUCCESS as c_int;

#[repr(C)]
struct __IOHIDManager(c_void);
pub type IOHIDManagerRef = *mut __IOHIDManager;
declare_TCFType!(IOHIDManager, IOHIDManagerRef);
impl_TCFType!(IOHIDManager, IOHIDManagerRef, IOHIDManagerGetTypeID);
impl_CFTypeDescription!(IOHIDManager);

// impl fmt::Debug for IOHIDManager {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_tuple("IOHIDManager").finish()
//     }
// }

unsafe impl Send for IOHIDManager {}
unsafe impl Sync for IOHIDManager {}

#[repr(C)]
struct __IOHIDDevice(c_void);
pub type IOHIDDeviceRef = *mut __IOHIDDevice;
declare_TCFType!(IOHIDDevice, IOHIDDeviceRef);
impl_TCFType!(IOHIDDevice, IOHIDDeviceRef, IOHIDDeviceGetTypeID);
impl_CFTypeDescription!(IOHIDDevice);

// impl fmt::Debug for IOHIDDevice {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_tuple("IOHIDDevice").finish()
//     }
// }

unsafe impl Send for IOHIDDevice {}
unsafe impl Sync for IOHIDDevice {}

pub struct Sendable<T>(*mut T);

impl<T> Sendable<T> {
    #[inline]
    pub fn new(inner: *mut T) -> Self {
        Self(inner)
    }

    #[inline]
    pub fn retain(inner: *mut T) -> Self {
        unsafe { CFRetain(inner as *mut c_void) };
        Self::new(inner)
    }
}

unsafe impl<T> Send for Sendable<T> {}

impl<T> Deref for Sendable<T> {
    type Target = *mut T;
    fn deref(&self) -> &*mut T {
        &self.0
    }
}

impl<T> Drop for Sendable<T> {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut c_void) };
    }
}

pub type SendableRunLoop = Sendable<__CFRunLoop>;

#[repr(C)]
pub struct CFRunLoopObserverContext {
    pub version: CFIndex,
    pub info: *mut c_void,
    pub retain: Option<extern "C" fn(info: *const c_void) -> *const c_void>,
    pub release: Option<extern "C" fn(info: *const c_void)>,
    pub copyDescription: Option<extern "C" fn(info: *const c_void) -> CFStringRef>,
}

impl CFRunLoopObserverContext {
    pub fn new(context: *mut c_void) -> Self {
        Self {
            version: 0 as CFIndex,
            info: context,
            retain: None,
            release: None,
            copyDescription: None,
        }
    }
}

pub struct CFRunLoopEntryObserver {
    observer: CFRunLoopObserverRef,
    // Keep alive until the observer goes away.
    context_ptr: *mut CFRunLoopObserverContext,
}

impl CFRunLoopEntryObserver {
    pub fn new(callback: CFRunLoopObserverCallBack, context: *mut c_void) -> Self {
        let context = CFRunLoopObserverContext::new(context);
        let context_ptr = Box::into_raw(Box::new(context));

        let observer = unsafe {
            CFRunLoopObserverCreate(
                kCFAllocatorDefault,
                kCFRunLoopEntry,
                false as Boolean,
                0,
                callback,
                context_ptr,
            )
        };

        Self {
            observer,
            context_ptr,
        }
    }

    pub fn add_to_current_runloop(&self) {
        unsafe {
            CFRunLoopAddObserver(CFRunLoopGetCurrent(), self.observer, kCFRunLoopDefaultMode)
        };
    }
}

impl Drop for CFRunLoopEntryObserver {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.observer as *mut c_void);

            // Drop the CFRunLoopObserverContext.
            let _ = Box::from_raw(self.context_ptr);
        };
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

pub fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: IOHIDManagerOptions) -> IOHIDManager {
    unsafe {
        let r = _IOHIDManagerCreate(allocator, options);
        TCFType::wrap_under_create_rule(r)
    }
}

pub fn IOHIDManagerSetDeviceMatching(manager: IOHIDManager, matching: CFDictionary) {
    unsafe {
        _IOHIDManagerSetDeviceMatching(
            manager.as_concrete_TypeRef(),
            matching.as_concrete_TypeRef(),
        )
    }
}

pub fn IOHIDManagerRegisterDeviceMatchingCallback(
    manager: IOHIDManager,
    callback: IOHIDDeviceCallback,
    context: *mut c_void,
) {
    unsafe {
        _IOHIDManagerRegisterDeviceMatchingCallback(
            manager.as_concrete_TypeRef(),
            callback,
            context,
        )
    }
}

pub fn IOHIDManagerRegisterDeviceRemovalCallback(
    manager: IOHIDManager,
    callback: IOHIDDeviceCallback,
    context: *mut c_void,
) {
    unsafe {
        _IOHIDManagerRegisterDeviceRemovalCallback(manager.as_concrete_TypeRef(), callback, context)
    }
}

pub fn IOHIDManagerOpen(
    manager: IOHIDManager,
    options: IOHIDManagerOptions,
) -> Result<(), IOReturn> {
    let e = unsafe { _IOHIDManagerOpen(manager.as_concrete_TypeRef(), options) };

    match e {
        kIOReturnSuccess => Ok(()),
        e => Err(e),
    }
}

pub fn IOHIDManagerClose(
    manager: IOHIDManager,
    options: IOHIDManagerOptions,
) -> Result<(), IOReturn> {
    let e = unsafe { _IOHIDManagerClose(manager.as_concrete_TypeRef(), options) };

    match e {
        kIOReturnSuccess => Ok(()),
        e => Err(e),
    }
}

pub fn IOHIDManagerScheduleWithRunLoop(
    manager: IOHIDManager,
    runLoop: CFRunLoopRef,
    runLoopMode: CFStringRef,
) {
    unsafe { _IOHIDManagerScheduleWithRunLoop(manager.as_concrete_TypeRef(), runLoop, runLoopMode) }
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    // CFRunLoop
    pub fn CFRunLoopObserverCreate(
        allocator: CFAllocatorRef,
        activities: CFOptionFlags,
        repeats: Boolean,
        order: CFIndex,
        callout: CFRunLoopObserverCallBack,
        context: *mut CFRunLoopObserverContext,
    ) -> CFRunLoopObserverRef;

    // IOHIDManager
    fn IOHIDManagerGetTypeID() -> CFTypeID;

    #[link_name = "IOHIDManagerCreate"]
    fn _IOHIDManagerCreate(
        allocator: CFAllocatorRef,
        options: IOHIDManagerOptions,
    ) -> IOHIDManagerRef;
    #[link_name = "IOHIDManagerSetDeviceMatching"]
    fn _IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFDictionaryRef);
    #[link_name = "IOHIDManagerRegisterDeviceMatchingCallback"]
    fn _IOHIDManagerRegisterDeviceMatchingCallback(
        manager: IOHIDManagerRef,
        callback: IOHIDDeviceCallback,
        context: *mut c_void,
    );
    #[link_name = "IOHIDManagerRegisterDeviceRemovalCallback"]
    fn _IOHIDManagerRegisterDeviceRemovalCallback(
        manager: IOHIDManagerRef,
        callback: IOHIDDeviceCallback,
        context: *mut c_void,
    );
    // pub fn IOHIDManagerRegisterInputReportCallback(
    //     manager: IOHIDManagerRef,
    //     callback: IOHIDReportCallback,
    //     context: *mut c_void,
    // );
    #[link_name = "IOHIDManagerOpen"]
    fn _IOHIDManagerOpen(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    #[link_name = "IOHIDManagerClose"]
    fn _IOHIDManagerClose(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    #[link_name = "IOHIDManagerScheduleWithRunLoop"]
    fn _IOHIDManagerScheduleWithRunLoop(
        manager: IOHIDManagerRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );

    // IOHIDDevice
    fn IOHIDDeviceGetTypeID() -> CFTypeID;
    #[link_name = "IOHIDDeviceSetReport"]
    fn _IOHIDDeviceSetReport(
        device: IOHIDDeviceRef,
        reportType: IOHIDReportType,
        reportID: CFIndex,
        report: *const u8,
        reportLength: CFIndex,
    ) -> IOReturn;
    // pub fn IOHIDDeviceGetProperty(device: IOHIDDeviceRef, key: CFStringRef) -> CFTypeRef;
    #[link_name = "IOHIDDeviceRegisterInputReportCallback"]
    fn _IOHIDDeviceRegisterInputReportCallback(
        device: IOHIDDeviceRef,
        report: *const u8,
        reportLength: CFIndex,
        callback: IOHIDReportCallback,
        context: *mut c_void,
    ) -> IOReturn;
    #[link_name = "IOHIDDeviceScheduleWithRunLoop"]
    fn _IOHIDDeviceScheduleWithRunLoop(
        device: IOHIDDeviceRef,
        runLoop: CFRunLoopRef,
        runLoopMode: CFStringRef,
    );
    #[link_name = "IOHIDDeviceClose"]
    fn _IOHIDDeviceClose(device: IOHIDDeviceRef, options: IOOptionBits) -> IOReturn;
    #[link_name = "IOHIDDeviceOpen"]
    fn _IOHIDDeviceOpen(device: IOHIDDeviceRef, options: IOOptionBits) -> IOReturn;
}

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::raw::c_void;
    use std::ptr;
    use std::sync::mpsc::{channel, Sender};
    use std::thread;

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        let tx: &Sender<SendableRunLoop> = unsafe { &*(context as *mut _) };

        // Send the current runloop to the receiver to unblock it.
        let _ = tx.send(SendableRunLoop::retain(unsafe { CFRunLoopGetCurrent() }));
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
                let manager = IOHIDManagerCreate(kCFAllocatorDefault, 0);
                assert!(!manager.0.is_null());

                IOHIDManagerScheduleWithRunLoop(
                    manager,
                    CFRunLoopGetCurrent(),
                    kCFRunLoopDefaultMode,
                );
                IOHIDManagerSetDeviceMatching(manager, ptr::null_mut());

                let rv = IOHIDManagerOpen(manager, 0);
                assert_eq!(rv, 0);

                // This will run until `CFRunLoopStop()` is called.
                CFRunLoopRun();

                let rv = IOHIDManagerClose(manager, 0);
                assert_eq!(rv, 0);

                CFRelease(manager.0 as *mut c_void);
            }
        });

        // Block until we enter the CFRunLoop.
        let runloop: SendableRunLoop = rx.recv().expect("failed to receive runloop");

        // Stop the runloop.
        unsafe { CFRunLoopStop(*runloop) };

        // Stop the thread.
        thread.join().expect("failed to join the thread");

        // Try to stop the runloop again (without crashing).
        unsafe { CFRunLoopStop(*runloop) };
    }
}
