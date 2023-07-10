use std::{fmt, mem::size_of, pin::Pin};

use async_trait::async_trait;
use futures::{stream::BoxStream, Stream};
use tokio::sync::mpsc;

use tokio_stream::wrappers::ReceiverStream;
use windows::{
    core::{HRESULT, HSTRING},
    Devices::{
        Enumeration::{DeviceInformation, DeviceInformationUpdate, DeviceWatcher},
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
    traits::{USBDevice, USBDeviceInfo, USBDeviceManager, WatchEvent},
    HidError, HidReportBytes, HidSendReportBytes, Result, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID,
};

pub struct WindowsDeviceWatcher {
    watcher: Pin<Box<DeviceWatcher>>,
    stream: ReceiverStream<WatchEvent<USBDeviceInfoImpl>>,
}

lazy_static! {
    static ref FIDO_SELECTOR: HSTRING =
        HidDevice::GetDeviceSelector(FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID)
            .expect("unable to create DeviceSelector");
}

trait WindowsErrorMapper<T> {
    fn map_win_err(self, msg: &str) -> Result<T>;
}

impl<T> WindowsErrorMapper<T> for windows::core::Result<T> {
    fn map_win_err(self, msg: &str) -> Result<T> {
        self.map_err(|e| {
            // TODO: sensible things
            error!("{msg}: 0x{:08X}: {e}", e.code().0);
            HidError::Internal
        })
    }
}

impl WindowsDeviceWatcher {
    fn new() -> Result<Self> {
        let watcher = DeviceInformation::CreateWatcherAqsFilter(&FIDO_SELECTOR).map_err(|e| {
            error!("creating DeviceWatcher: {e}");
            HidError::Internal
        })?;

        let watcher = Box::pin(watcher);
        let (tx, rx) = mpsc::channel(16);
        let stream = ReceiverStream::from(rx);

        let tx_add = tx.clone();
        watcher
            .Added(&TypedEventHandler::<_, DeviceInformation>::new(
                move |_, info| {
                    let info = info.as_ref().ok_or::<HRESULT>(ERROR_BAD_ARGUMENTS.into())?;

                    tx_add
                        .blocking_send(WatchEvent::Added(USBDeviceInfoImpl { info: info.clone() }))
                        .map_err(|_| ERROR_HANDLES_CLOSED.into())
                },
            ))
            .map_win_err("adding DeviceWatcher::Added listener")?;

        let tx_removed = tx.clone();
        watcher
            .Removed(&TypedEventHandler::<_, DeviceInformationUpdate>::new(
                move |_, update| {
                    let info = update
                        .as_ref()
                        .ok_or::<HRESULT>(ERROR_BAD_ARGUMENTS.into())?;
                    tx_removed
                        .blocking_send(WatchEvent::Removed(info.Id()?))
                        .map_err(|_| ERROR_HANDLES_CLOSED.into())
                },
            ))
            .map_win_err("adding DeviceWatcher::Removed listener")?;

        watcher
            .EnumerationCompleted(&TypedEventHandler::<_, _>::new(move |_, _| {
                tx.blocking_send(WatchEvent::EnumerationComplete)
                    .map_err(|_| ERROR_HANDLES_CLOSED.into())
            }))
            .map_win_err("adding DeviceWatcher::EnumerationCompleted listener")?;

        // trace!("Starting WindowsDeviceWatcher");
        watcher.Start().map_win_err("DeviceWatcher::Start")?;

        Ok(Self { watcher, stream })
    }
}

impl Drop for WindowsDeviceWatcher {
    fn drop(&mut self) {
        if let Err(e) = self.watcher.Stop() {
            error!("DeviceWatcher::Stop: {e}");
        }
    }
}

impl Stream for WindowsDeviceWatcher {
    type Item = WatchEvent<USBDeviceInfoImpl>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        ReceiverStream::poll_next(Pin::new(&mut Pin::get_mut(self).stream), cx)
    }
}

#[derive(Debug)]
pub struct USBDeviceManagerImpl {}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = HSTRING;

    async fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>> {
        // trace!("watch_devices");
        Ok(Box::pin(WindowsDeviceWatcher::new()?))
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>> {
        let ret = DeviceInformation::FindAllAsyncAqsFilter(&FIDO_SELECTOR)
            .map_win_err("getting DeviceInformation::FindAllAsyncAqsFilter future")?
            .await
            .map_win_err(
                "enumerating connected devices (DeviceInformation::FindAllAsyncAqsFilter)",
            )?;

        Ok(ret
            .into_iter()
            .map(|info| USBDeviceInfoImpl { info })
            .collect())
    }

    async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[derive(Clone)]
pub struct USBDeviceInfoImpl {
    info: DeviceInformation,
}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = HSTRING;

    async fn open(self) -> Result<Self::Device> {
        USBDeviceImpl::new(self).await
    }
}

impl fmt::Debug for USBDeviceInfoImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsUSBDeviceInfo")
            .field("id", &self.info.Id().unwrap_or_default().to_string())
            .field("name", &self.info.Name().unwrap_or_default().to_string())
            .finish()
    }
}

#[derive(Debug)]
pub struct USBDeviceImpl {
    device: HidDevice,
    info: USBDeviceInfoImpl,
    listener_token: EventRegistrationToken,
    rx: mpsc::Receiver<HidInputReport>,
}

impl Drop for USBDeviceImpl {
    fn drop(&mut self) {
        if let Err(e) = self.device.RemoveInputReportReceived(self.listener_token) {
            error!("HidDevice::RemoveInputReportReceived: {e}");
        }
    }
}

impl USBDeviceImpl {
    async fn new(info: USBDeviceInfoImpl) -> Result<Self> {
        trace!("Opening device: {info:?}");
        let device_id = info.info.Id().map_win_err("unable to get device ID")?;

        // For USB HID FIDO authenticators when *not* running as Administrator,
        // HidDevice::FromIdAsync returns `null` and HRESULT = 0, so you end up
        // with `Err(The operation completed successfully.)`:
        // https://learn.microsoft.com/en-us/uwp/api/windows.devices.humaninterfacedevice?view=winrt-22621#troubleshooting
        //
        // Unhelpfully, DeviceAccessInformation::CurrentStatus returns "Allowed"
        // for non-UWP apps, so we can't even use the approach described here:
        // https://learn.microsoft.com/en-us/answers/questions/35914/hiddevice-fromidasync-returns-null-for-my-usb-keyb#comment-36699
        let device = match HidDevice::FromIdAsync(&device_id, FileAccessMode::ReadWrite)
            .map_win_err("getting HidDevice::FromIdAsync future")?
            .await
        {
            Ok(d) => d,
            Err(e) => {
                if e.code() == HRESULT(0) {
                    error!("cannot open {device_id:?}, are you running as Administrator?");
                    return Err(HidError::PermissionDenied);
                } else {
                    return Err(e).map_win_err("opening device (HidDevice::FromIdAsync)");
                }
            }
        };

        // HidDevice returns data using the InputReportReceived event. Stash the
        // data into a channel to pick up later.
        let (tx, rx) = mpsc::channel(100);
        let listener_token = device
            .InputReportReceived(
                &TypedEventHandler::<_, HidInputReportReceivedEventArgs>::new(move |_, args| {
                    let args = args.as_ref().ok_or::<HRESULT>(ERROR_BAD_ARGUMENTS.into())?;
                    let report = args.Report()?;
                    tx.blocking_send(report)
                        .map_err(|_| ERROR_HANDLES_CLOSED.into())
                }),
            )
            .map_win_err("HidInputDevice::InputReportReceived")?;

        let o = USBDeviceImpl {
            device,
            info,
            listener_token,
            rx,
        };
        Ok(o)
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
        let ret = ret.ok_or(HidError::Closed)?;
        let buf = ret
            .Data()
            .map_win_err("reading HidInputReport (HidInputReport::Data)")?;
        let len = buf
            .Length()
            .map_win_err("reading HidInputReport (IBuffer::Length)")? as usize;
        if len != size_of::<HidReportBytes>() + 1 {
            return Err(HidError::InvalidMessageLength);
        }
        let dr = DataReader::FromBuffer(&buf)
            .map_win_err("reading HidInputReport (DataReader::FromBuffer)")?;

        let mut o = [0; size_of::<HidReportBytes>()];
        // Drop the leading report ID byte
        dr.ReadByte().ok();
        dr.ReadBytes(&mut o)
            .map_win_err("reading HidInputReport (DataReader::ReadBytes)")?;

        Ok(o)
    }

    async fn write(&mut self, data: HidSendReportBytes) -> Result<()> {
        let report = self
            .device
            .CreateOutputReportById(data[0] as u16)
            .map_win_err("writing HidOutputReport (CreateOutputReportById)")?;
        {
            let dw = DataWriter::new().map_win_err("writing HidOutputReport (DataWriter::new)")?;
            dw.WriteBytes(&data[..])
                .map_win_err("writing HidOutputReport (DataWriter::WriteBytes)")?;

            let buffer = dw
                .DetachBuffer()
                .map_win_err("writing HidOutputReport (DataWriter::DetachBuffer)")?;

            report
                .SetData(&buffer)
                .map_win_err("writing HidOutputReport (HidOutputReport::SetData)")?;
        }
        let ret = self
            .device
            .SendOutputReportAsync(&report)
            .map_win_err("writing HidOutputReport (HidDevice::SendOutputReportAsync future)")?
            .await
            .map_win_err("writing HidOutputReport (HidDevice::SendOutputReportAsync result)")?;

        if ret as usize != size_of::<HidSendReportBytes>() {
            error!("unexpected HidDevice::SendOutputReportAsync length ({ret})");
            return Err(HidError::SendError);
        }
        Ok(())
    }
}
