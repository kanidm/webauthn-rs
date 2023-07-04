#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/linux_wrapper.rs"));

use nix::ioctl_read;
use num_derive::FromPrimitive;

// The userspace API is lies: https://bugzilla.kernel.org/show_bug.cgi?id=217463
ioctl_read!(hid_ioc_rd_desc_size, b'H', 0x01, u32);
ioctl_read!(hid_ioc_rd_desc, b'H', 0x02, hidraw_report_descriptor);
ioctl_read!(hid_ioc_raw_info, b'H', 0x03, hidraw_devinfo);

impl hidraw_report_descriptor {
    pub fn get_value(&self) -> &[u8] {
        &self.value[..HID_MAX_DESCRIPTOR_SIZE.min(self.size.max(0)) as usize]
    }
}

/// Linux input bus type.
#[derive(Debug, FromPrimitive, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BusType {
    Usb = BUS_USB,
    Bluetooth = BUS_BLUETOOTH,
    Virtual = BUS_VIRTUAL,
}
