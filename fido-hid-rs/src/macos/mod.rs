//! macOS / IOKit USB HID implementation.
//!
//! This module is based on [Mozilla authenticator-rs][0]' macOS platform
//! support library, but has a lot of changes to it.
//!
//! ## Overview
//!
//! **Rant:** IOKit is a giant pain to work with outside a [`CFRunLoop`], and
//! macOS' platform Rust bindings aren't nearly as well-polished as Windows'.
//! This module attempts to shoe-horn these structures into Rust (and `tokio`)
//! as best as possible.
//!
//! We need to keep [`IOHIDManager`] and its [`CFRunLoop`] around for as long as
//! there are *any* [`IOHIDDevice`] references created by it, because otherwise
//! they'll be [automatically closed][1] (and [there's no way around that][2]).
//! For that we use [`IOHIDManagerWrapper`], which gets wrapped in an [`Arc`]
//! and shared between [`USBDeviceManagerImpl`] and [`USBDeviceInfoImpl`].
//!
//! Whenever a device is opened, [`USBDeviceImpl`] starts up a new thread with
//! another [`CFRunLoop`] to drive events from [`IOHIDDevice`]. This gets
//! terminated once the [`USBDeviceImpl`] gets dropped.
//!
//! Internally these use `tokio` channels to pass state from callbacks in the
//! [`CFRunLoop`] into Rust async land.
//!
//! [0]: https://github.com/mozilla/authenticator-rs
//! [1]: https://developer.apple.com/library/archive/technotes/tn2187/_index.html#//apple_ref/doc/uid/DTS10004224-CH1-SOURCECODE15
//! [2]: https://github.com/apple-oss-distributions/IOKitUser/blob/b0b3f822b7507c265aa8a1e37c3100c03ca82039/hid.subproj/IOHIDManager.c#L974-L975

use async_trait::async_trait;
use core_foundation::{
    base::CFIndex,
    runloop::{CFRunLoop, CFRunLoopActivity, CFRunLoopObserverRef, CFRunLoopRun},
};
use futures::{
    stream::{self, BoxStream},
    StreamExt,
};
use libc::c_void;
use std::{
    fmt::{self, Debug},
    marker::PhantomPinned,
    mem::size_of,
    ops::Deref,
    pin::Pin,
    slice::from_raw_parts,
    sync::Arc,
};
use tokio::{
    spawn,
    sync::{
        broadcast,
        mpsc::{self, Receiver, Sender},
    },
    task::spawn_blocking,
};
use tokio_stream::wrappers::BroadcastStream;

mod iokit;

use self::iokit::{
    CFRunLoopEntryObserver, IOHIDDevice, IOHIDDeviceRef, IOHIDManager, IOHIDManagerOptions,
    IOHIDReportType, IOReturn, Sendable,
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
///
/// The [IOHIDManager] must be dropped last.
#[derive(Debug)]
struct IOHIDManagerWrapper {
    runloop: Sendable<CFRunLoop>,
    manager: IOHIDManager,
}

#[derive(Debug)]
enum IOHIDManagerEvent {
    Matching(IOHIDDevice),
    Removal(IOHIDDevice),
}

impl IOHIDManagerWrapper {
    /// Creates a new [IOHIDManager] and starts a [CFRunLoop] to process events.
    async fn new(tx: Sender<IOHIDManagerEvent>) -> Option<Arc<Self>> {
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

            // IOHIDManagerClose reports an error if we have closed one of its
            // IOHIDDevices, but it'll still close all devices and clean up.
            let _ = manager_worker.close(IOHIDManagerOptions::empty());
            // trace!("MacDeviceMatcher finished");
        });

        // returns None if observer_tx is dropped before Self::observe (ie:
        // worker thread dropped)
        let runloop = observer_rx.recv().await?;

        Some(Arc::new(Self { manager, runloop }))
    }

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        // trace!("fetching MacDeviceMatcher RunLoop...");
        let tx: &Sender<Sendable<CFRunLoop>> = unsafe { &*(context as *const _) };
        let _ = tx.blocking_send(Sendable(CFRunLoop::get_current()));
    }

    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        assert!(!context.is_null());
        let tx: &Pin<Box<Sender<IOHIDManagerEvent>>> = unsafe { &*(context as *const _) };
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
        let tx: &Pin<Box<Sender<IOHIDManagerEvent>>> = unsafe { &*(context as *const _) };
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
        let manager = IOHIDManagerWrapper::new(native_tx).await.ok_or_else(|| {
            error!("could not setup IOHIDManagerWrapper thread");
            HidError::Internal
        })?;

        let (tx, rx) = broadcast::channel(MESSAGE_QUEUE_LENGTH);
        let manager_wrapper = manager.clone();
        spawn(async move {
            // Worker to handle the native events
            while let Some(e) = native_rx.recv().await {
                let o = match e {
                    IOHIDManagerEvent::Matching(device) => WatchEvent::Added(USBDeviceInfoImpl {
                        device,
                        _manager_wrapper: manager_wrapper.clone(),
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
                _manager_wrapper: self.manager.clone(),
            })
            .collect())
    }
}

#[derive(Clone)]
pub struct USBDeviceInfoImpl {
    device: IOHIDDevice,

    /// The [IOHIDManagerWrapper] which owns this [IOHIDDevice].
    ///
    /// This keeps the [IOHIDManager]'s [CFRunLoop] alive for as long as any
    /// device is referenced.
    _manager_wrapper: Arc<IOHIDManagerWrapper>,
}

impl Debug for USBDeviceInfoImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBDeviceInfoImpl")
            .field("device", &self.device)
            .finish()
    }
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
    info: Arc<USBDeviceInfoImpl>,
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
        let info = Arc::new(info);
        let (worker, rx) = MacUSBDeviceWorker::new(info.clone());

        let (observer_tx, mut observer_rx) = mpsc::channel(1);

        spawn_blocking(move || {
            // trace!("started device thread");
            let context = &observer_tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(Self::observe, context);
            obs.add_to_current_runloop();
            worker.start()
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
    info: Arc<USBDeviceInfoImpl>,
    // Receiver, from perspective of worker (authenticator -> initiator)
    rx: Sender<HidReportBytes>,
    _pin: PhantomPinned,
}

impl MacUSBDeviceWorker {
    fn new(info: Arc<USBDeviceInfoImpl>) -> (Self, Receiver<HidReportBytes>) {
        let (rx, tx) = mpsc::channel(MESSAGE_QUEUE_LENGTH);
        (
            Self {
                info,
                rx,
                _pin: PhantomPinned,
            },
            tx,
        )
    }

    /// Registers event handlers for the [IODevice] and starts the [CFRunLoop].
    ///
    /// This method blocks until completion.
    fn start(&self) -> Result<()> {
        let context = self as *const Self as *const c_void;
        let runloop = CFRunLoop::get_current();
        let mut buf = [0; size_of::<HidReportBytes>()];
        self.info.device.register_input_report_callback(
            buf.as_mut_ptr(),
            buf.len(),
            Self::on_input_report,
            context,
        );
        self.info.device.schedule_with_run_loop(&runloop);
        self.info.device.open(0)?;

        // trace!("starting device runloop");
        unsafe {
            CFRunLoopRun();
        }

        // trace!("MacUSBDeviceWorker runloop done, cleaning up");
        self.info.device.unschedule_from_run_loop(&runloop);
        self.info.device.close(0)?;
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

        let this = unsafe { &*(context as *const Self) };
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
