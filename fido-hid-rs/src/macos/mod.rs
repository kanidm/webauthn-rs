/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! macOS / IOKit USB HID implementation.
//!
//! This module is based on [Mozilla authenticator-rs][0]' macOS platform
//! support library, but has a lot of changes to it.
//!
//! ## Overview
//!
//! **Rant:** IOKit is a giant pain to work with outside a [`CFRunLoop`], and
//! macOS' platform Rust bindings aren't nearly as well-polished as Windows'.
//! This module attempts to work around that as best as possible.
//!
//! When new devices are discovered, [`USBDeviceImpl`] starts up a new thread to
//! drive the [`CFRunLoop`] for [`IOHIDDevice`].
//!
//! [0]: https://github.com/mozilla/authenticator-rs
//! [`CFRunLoop`]: core_foundation::runloop::CFRunLoop

use async_trait::async_trait;
use core_foundation::{
    base::CFIndex,
    runloop::{
        CFRunLoop, CFRunLoopActivity, CFRunLoopObserverRef, CFRunLoopRun, CFRunLoopTimerRef,
    },
};
use futures::{
    stream::{self, BoxStream},
    Stream, StreamExt,
};
use libc::c_void;
use std::{
    fmt,
    marker::{PhantomData, PhantomPinned},
    mem::size_of,
    ops::Deref,
    pin::Pin,
    slice::from_raw_parts,
    sync::Arc,
    time::Duration,
};
use tokio::{
    spawn,
    sync::{
        broadcast,
        mpsc::{self, Receiver, Sender},
    },
    task::spawn_blocking,
};
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};

mod iokit;

use self::iokit::{
    CFRunLoopEntryObserver, IOHIDDevice, IOHIDDeviceMatcher, IOHIDDeviceRef,
    IOHIDManager, IOHIDManagerOptions, IOHIDReportType, IOReturn, Sendable,
};
use crate::{
    HidError, HidReportBytes, HidSendReportBytes, Result, USBDevice, USBDeviceInfo,
    USBDeviceManager, WatchEvent,
};

const MESSAGE_QUEUE_LENGTH: usize = 16;

/// Wrapper for [IOHIDManager] to keep its [CFRunLoop] running while there are
/// active usages of [IOHIDDevice] objects created by the manager.
/// 
/// The intended usage of this object is wrapped in an [Arc], so that it stays
/// alive as long as anything needs it.
#[derive(Debug)]
struct IOHIDManagerWrapper {
    manager: IOHIDManager,
    runloop: Sendable<CFRunLoop>,
}

#[derive(Debug)]
enum IOHIDManagerEvent {
    Matching(IOHIDDevice),
    Removal(IOHIDDevice),
    // todo
}

impl IOHIDManagerWrapper {
    async fn new(tx: Sender<IOHIDManagerEvent>) -> Option<Self> {
        let tx = Box::pin(tx);
        let manager = IOHIDManager::create(IOHIDManagerOptions::empty());
        let (observer_tx, mut observer_rx) = mpsc::channel(1);

        let manager_worker = manager.clone();
        spawn_blocking(move || {
            let context = &observer_tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(Self::observe, context);
            obs.add_to_current_runloop();

            let context = &tx as *const _ as *mut c_void;
            let runloop = CFRunLoop::get_current();

            // Match FIDO devices only.
            let matcher = IOHIDDeviceMatcher::new();
            manager_worker.set_device_matching(Some(&matcher));
            manager_worker.register_device_matching_callback(Self::on_device_matching, context);
            manager_worker.register_device_removal_callback(Self::on_device_removal, context);
            manager_worker.schedule_with_run_loop(&runloop);
            manager_worker.open(IOHIDManagerOptions::empty()).unwrap();

            // trace!("starting IOHIDManagerWrapper runloop");
            unsafe {
                CFRunLoopRun();
            }

            // trace!("IOHIDManagerWrapper runloop done, cleaning up");
            manager_worker.unschedule_from_run_loop(&runloop);
            manager_worker.close(IOHIDManagerOptions::empty()).unwrap();
            // trace!("MacDeviceMatcher finished");
            return;
        });

        let runloop = observer_rx.recv().await?;

        Some(Self { manager, runloop })
    }

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        // trace!("fetching MacDeviceMatcher RunLoop...");
        let tx: &Sender<Sendable<CFRunLoop>> = unsafe { &*(context as *mut _) };
        let _ = tx.blocking_send(Sendable(CFRunLoop::get_current()));
    }

    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let tx: &Pin<Box<Sender<IOHIDManagerEvent>>> = unsafe { &*(context as *mut _) };
        let device = device_ref.into();
        // trace!("on_device_matching: {device:?}");
        let _ = tx.blocking_send(IOHIDManagerEvent::Matching(device));
    }

    extern "C" fn on_device_removal(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let tx: &Pin<Box<Sender<IOHIDManagerEvent>>> = unsafe { &*(context as *mut _) };
        let device = device_ref.into();
        // trace!("on_device_removal: {device:?}");
        let _ = tx.blocking_send(IOHIDManagerEvent::Removal(device));
    }
}

impl Deref for IOHIDManagerWrapper {
    type Target = IOHIDManager;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

impl Drop for IOHIDManagerWrapper {
    fn drop(&mut self) {
        trace!("dropping IOHIDManagerWrapper");
        self.runloop.stop();
    }
}

#[derive(Debug)]
pub struct USBDeviceManagerImpl {
    manager: Arc<IOHIDManagerWrapper>,
    rx: broadcast::Receiver<WatchEvent<USBDeviceInfoImpl>>,
}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = IOHIDDevice;

    async fn new() -> Result<Self> {
        let (native_tx, mut native_rx) = mpsc::channel(MESSAGE_QUEUE_LENGTH);
        let manager = Arc::new(IOHIDManagerWrapper::new(native_tx).await.ok_or_else(|| {
            error!("could not setup IOHIDManagerWrapper thread");
            HidError::Internal
        })?);

        let (tx, rx) = broadcast::channel(MESSAGE_QUEUE_LENGTH);
        let manager_wrapper = manager.clone();
        spawn(async move {
            // Worker to handle the native events
            while let Some(e) = native_rx.recv().await {
                let o = match e {
                    IOHIDManagerEvent::Matching(device) => WatchEvent::Added(USBDeviceInfoImpl {
                        device,
                        manager_wrapper: manager_wrapper.clone(),
                    }),
                    IOHIDManagerEvent::Removal(device) => WatchEvent::Removed(device),
                };

                if let Err(e) = tx.send(o) {
                    error!("could not broadcast native event: {e:?}");
                    break;
                }
            }
        });

        Ok(Self { manager, rx })
    }

    /*
       async fn watch_devices(&mut self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>> {
           let (mut matcher, rx) = MacDeviceMatcher::new()?;
           let (observer_tx, mut observer_rx) = mpsc::channel(1);
           let stream = ReceiverStream::from(rx);

           spawn_blocking(move || {
               let context = &observer_tx as *const _ as *mut c_void;
               let obs = CFRunLoopEntryObserver::new(Self::observe, context);
               obs.add_to_current_runloop();
               matcher.as_mut().start()
           });

           // trace!("Waiting for manager runloop");
           let runloop = observer_rx.recv().await.ok_or_else(|| {
               error!("failed to receive MacDeviceMatcher CFRunLoop");
               HidError::Internal
           })?;
           // trace!("Got a manager runloop");

           Ok(Box::pin(MacRunLoopStream { runloop, stream }))
       }
    */

    async fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>> {
        let existing_devices =
            stream::iter(self.get_devices().await?.into_iter().map(WatchEvent::Added));
        let enumeration_completed = stream::iter(vec![WatchEvent::EnumerationComplete]);
        let receiver = self.rx.resubscribe();
        let broadcast = BroadcastStream::new(receiver).filter_map(|x| async move { x.ok() });

        Ok(Box::pin(
            existing_devices
                .chain(enumeration_completed)
                .chain(broadcast),
        ))
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>> {
        let devices = self.manager.copy_devices();

        Ok(devices
            .into_iter()
            .map(|device| USBDeviceInfoImpl {
                device,
                manager_wrapper: self.manager.clone(),
            })
            .collect())
    }
}

/*
impl<'a> USBDeviceManagerImpl<'a> {
    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        // trace!("fetching MacDeviceMatcher RunLoop...");
        let tx: &Sender<Sendable<CFRunLoop>> = unsafe { &*(context as *mut _) };
        let _ = tx.blocking_send(Sendable(CFRunLoop::get_current()));
    }

    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let tx: &broadcast::Sender<WatchEvent<USBDeviceInfoImpl>> =
            unsafe { &*(context as *mut _) };
        let device = device_ref.into();
        // trace!("on_device_matching: {device:?}");
        let _ = tx.send(WatchEvent::Added(USBDeviceInfoImpl {
            device,
        }));
    }

    extern "C" fn on_device_removal(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let tx: &broadcast::Sender<WatchEvent<USBDeviceInfoImpl>> =
            unsafe { &*(context as *mut _) };
        let device = device_ref.into();
        // trace!("on_device_removal: {device:?}");
        let _ = tx.send(WatchEvent::Removed(device));
    }
}
 */
struct MacRunLoopStream<T> {
    runloop: Sendable<CFRunLoop>,
    stream: ReceiverStream<T>,
}

impl<T> Stream for MacRunLoopStream<T> {
    type Item = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let stream = unsafe { self.map_unchecked_mut(|s| &mut s.stream) };
        ReceiverStream::poll_next(stream, cx)
    }
}

impl<T> Drop for MacRunLoopStream<T> {
    fn drop(&mut self) {
        self.runloop.stop()
    }
}

/*
struct MacDeviceMatcher {
    manager: IOHIDManager,
    tx: Sender<WatchEvent<USBDeviceInfoImpl>>,
    _pin: PhantomPinned,
}

impl MacDeviceMatcher {
    fn new() -> Result<(Pin<Box<Self>>, Receiver<WatchEvent<USBDeviceInfoImpl>>)> {
        let manager = IOHIDManager::create(IOHIDManagerOptions::empty());

        let (tx, rx) = mpsc::channel(MESSAGE_QUEUE_LENGTH);
        let o = Self {
            manager,
            tx,
            _pin: PhantomPinned,
        };

        Ok((Box::pin(o), rx))
    }

    fn start(&self) -> Result<()> {
        let context = self as *const Self as *mut c_void;
        let runloop = CFRunLoop::get_current();

        // Match FIDO devices only.
        let matcher = IOHIDDeviceMatcher::new();
        self.manager.set_device_matching(Some(&matcher));
        self.manager
            .register_device_matching_callback(Self::on_device_matching, context);
        self.manager
            .register_device_removal_callback(Self::on_device_removal, context);
        self.manager.schedule_with_run_loop(&runloop);
        self.manager.open(IOHIDManagerOptions::empty())?;

        // IOHIDManager doesn't signal that it has "finished" enumerating, so
        // schedule a one-off timer on the CFRunLoop to fire in 2 seconds.
        let timer =
            CFRunLoopTimerHelper::new(Self::enumeration_complete, context, Duration::from_secs(2));
        timer.add_to_current_runloop();

        // trace!("starting MacDeviceMatcher runloop");
        unsafe {
            CFRunLoopRun();
        }

        // trace!("MacDeviceMatcher runloop done, cleaning up");
        drop(timer);
        self.manager.unschedule_from_run_loop(&runloop);
        self.manager.close(IOHIDManagerOptions::empty())?;
        // trace!("MacDeviceMatcher finished");
        Ok(())
    }

    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let this = unsafe { &mut *(context as *mut Self) };
        let device = device_ref.into();
        // trace!("on_device_matching: {device:?}");
        let _ = this
            .tx
            .blocking_send(WatchEvent::Added(USBDeviceInfoImpl { device }));
    }

    extern "C" fn on_device_removal(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let this = unsafe { &mut *(context as *mut Self) };
        let device = device_ref.into();
        // trace!("on_device_removal: {device:?}");
        let _ = this.tx.blocking_send(WatchEvent::Removed(device));
    }

    extern "C" fn enumeration_complete(_: CFRunLoopTimerRef, context: *mut c_void) {
        assert!(!context.is_null());
        let this = unsafe { &mut *(context as *mut Self) };
        // trace!("enumeration_complete");
        let _ = this.tx.blocking_send(WatchEvent::EnumerationComplete);
    }
}
*/

#[derive(Clone, Debug)]
pub struct USBDeviceInfoImpl {
    device: IOHIDDevice,
    manager_wrapper: Arc<IOHIDManagerWrapper>,
}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = IOHIDDevice;

    async fn open(self) -> Result<Self::Device> {
        USBDeviceImpl::new(self).await
    }
}

pub struct USBDeviceImpl {
    info: USBDeviceInfoImpl,
    rx: mpsc::Receiver<HidReportBytes>,
    runloop: Sendable<CFRunLoop>,
}

unsafe impl Send for USBDeviceImpl {}
unsafe impl Sync for USBDeviceImpl {}

impl fmt::Debug for USBDeviceImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBDeviceImpl")
            .field("info", &self.info)
            .field("runloop", &self.runloop)
            .finish()
    }
}

impl Drop for USBDeviceImpl {
    fn drop(&mut self) {
        self.runloop.stop();
    }
}

impl USBDeviceImpl {
    async fn new(info: USBDeviceInfoImpl) -> Result<USBDeviceImpl> {
        // trace!("Opening device: {info:?}");

        let device = IOHIDDevice::create(info.device.get_port());
        let (worker, rx) = MacUSBDeviceWorker::new(device);

        let (observer_tx, mut observer_rx) = mpsc::channel(1);

        spawn_blocking(move || {
            // trace!("started device thread");
            let context = &observer_tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(Self::observe, context);
            obs.add_to_current_runloop();
            worker.as_ref().start()
        });

        // trace!("waiting for a runloop for device");
        let runloop = observer_rx.recv().await.ok_or_else(|| {
            error!("failed to receive MacUSBDeviceWorker CFRunLoop");
            HidError::Internal
        })?;
        // trace!("got device runloop");

        Ok(Self { info, rx, runloop })
    }

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        assert!(!context.is_null());
        // trace!("fetching MacUSBDeviceWorker RunLoop...");
        let tx: &Sender<Sendable<CFRunLoop>> = unsafe { &*(context as *mut _) };
        let _ = tx.blocking_send(Sendable(CFRunLoop::get_current()));
    }
}

struct MacUSBDeviceWorker {
    device: IOHIDDevice,
    // Receiver, from perspective of worker (authenticator -> initiator)
    rx: Sender<HidReportBytes>,
    _pin: PhantomPinned,
}

impl MacUSBDeviceWorker {
    fn new(device: IOHIDDevice) -> (Pin<Box<Self>>, Receiver<HidReportBytes>) {
        let (rx, tx) = mpsc::channel(MESSAGE_QUEUE_LENGTH);
        (
            Box::pin(Self {
                device,
                rx,
                _pin: PhantomPinned,
            }),
            tx,
        )
    }

    fn start(&self) -> Result<()> {
        let context = self as *const Self as *const c_void;
        let runloop = CFRunLoop::get_current();
        let mut buf = [0; size_of::<HidReportBytes>()];
        self.device.register_input_report_callback(
            buf.as_mut_ptr(),
            buf.len(),
            Self::on_input_report,
            context,
        );
        self.device.schedule_with_run_loop(&runloop);
        self.device.open(0)?;

        // trace!("starting device runloop");
        unsafe {
            CFRunLoopRun();
        }

        // trace!("MacUSBDeviceWorker runloop done, cleaning up");
        self.device.unschedule_from_run_loop(&runloop);
        self.device.close(0)?;
        // This buffer needs to live while the RunLoop does
        let _ = &buf;
        // trace!("MacUSBDeviceWorker finished");
        Ok(())
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
        assert!(!context.is_null());
        assert!(!report.is_null());
        assert_eq!(report_len as usize, size_of::<HidReportBytes>());

        let this = unsafe { &mut *(context as *mut Self) };
        let src_data = unsafe { from_raw_parts(report, report_len as usize) };
        let mut data: HidReportBytes = [0; size_of::<HidReportBytes>()];
        data.copy_from_slice(src_data);
        let _ = this.rx.blocking_send(data);
    }
}

#[async_trait]
impl USBDevice for USBDeviceImpl {
    type Info = USBDeviceInfoImpl;

    fn get_info(&self) -> &Self::Info {
        &self.info
    }

    async fn read(&mut self) -> Result<HidReportBytes> {
        let ret = self.rx.recv().await;
        ret.ok_or(HidError::Closed)
    }

    async fn write(&mut self, data: HidSendReportBytes) -> Result<()> {
        let report_id = data[0];
        let data = &data[if report_id == 0 { 1 } else { 0 }..];
        Ok(self
            .info
            .device
            .set_report(IOHIDReportType::Output, CFIndex::from(report_id), data)?)
    }
}
