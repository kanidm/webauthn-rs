//! USB HID report descriptor parser.
//!
//! ## References
//!
//! * [Device Class Definition for Human Interface Devices, v1.11][0],
//!   §6.2.2 "Report Descriptor"
//!
//! [0]: https://www.usb.org/sites/default/files/documents/hid1_11.pdf

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};

/// HID descriptor tags; shifted right by 2 bits (removing the `bSize` field).
///
/// ## References
///
/// * [Device Class Definition for Human Interface Devices, v1.11][0],
///   §5.3 "Generic Item Format"
///
/// [0]: https://www.usb.org/sites/default/files/documents/hid1_11.pdf
#[allow(clippy::unusual_byte_groupings)] // groupings are bTag(4), bType(2)
#[derive(FromPrimitive)]
#[repr(u8)]
enum Tag {
    // Main items
    Input = 0b1000_00,
    Output = 0b1001_00,
    Feature = 0b1011_00,
    Collection = 0b1010_00,
    EndCollection = 0b1100_00,

    // Global items
    UsagePage = 0b0000_01,
    LogicalMinimum = 0b0001_01,
    LogicalMaximum = 0b0010_01,
    PhysicalMinimum = 0b0011_01,
    PhysicalMaximum = 0b0100_01,
    UnitExponent = 0b0101_01,
    Unit = 0b0110_01,
    ReportSize = 0b0111_01,
    ReportID = 0b1000_01,
    ReportCount = 0b1001_01,
    Push = 0b1010_01,
    Pop = 0b1011_01,

    // Local items
    Usage = 0b0000_10,
    UsageMinimum = 0b0001_10,
    UsageMaximum = 0b0010_10,
    DesignatorIndex = 0b0011_10,
    DesignatorMinimum = 0b0100_10,
    DesignatorMaximum = 0b0101_10,
    StringIndex = 0b0111_10,
    StringMinimum = 0b1000_10,
    StringMaximum = 0b1001_10,
    Delimiter = 0b1010_10,
}

/// Item in a report descriptor.
struct DescriptorItem<'a> {
    /// The tag of the item, if known.
    tag: Option<Tag>,

    /// The value of the item.
    value: &'a [u8],
}

/// Iterator-based report descriptor parser.
///
/// This returns each [item] in a descriptor, without regard to its context.
///
/// ## Limitations
///
/// This only fully supports short items. This will parse long items, but skip
/// the tag.
///
/// [item]: DescriptorItem
struct DescriptorIterator<'a> {
    i: &'a [u8],
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = DescriptorItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i.is_empty() {
            return None;
        }

        let tag;
        let value;

        let mut i0 = self.i[0];
        if i0 == 0xfe {
            // Long item: 0xfe [size] [tag] [data...]
            if self.i.len() < 3 {
                // Not enough bytes to get the long item length and tag
                return None;
            }

            let length = usize::from(self.i[1]);
            if self.i.len() < length + 3 {
                // Not enough bytes to get long item value
                return None;
            }
            warn!("long tags are not supported");
            tag = None;
            (value, self.i) = self.i[3..].split_at(length);
        } else {
            // Short item: [tag | type | size] [data...]
            let mut length = usize::from(i0 & 0x03);
            if length == 0x03 {
                length += 1;
            }
            i0 >>= 2;

            tag = Tag::from_u8(i0);
            // if tag.is_none() {
            //     warn!("unknown short tag: 0b{i0:b}",);
            // }
            if self.i.len() < length + 1 {
                // Not enough bytes to get short item value
                return None;
            }
            (value, self.i) = self.i[1..].split_at(length);
        }

        Some(DescriptorItem { tag, value })
    }
}

/// Parses a USB HID Report Descriptor to determine whether it is a FIDO
/// authenticator.
///
/// This only handles [`Tag::UsagePage`] and [`Tag::Usage`], so will only
/// support simple descriptors. This is should be sufficient for USB FIDO
/// authethicators.
pub fn is_fido_authenticator(descriptor: &[u8]) -> bool {
    let descriptor = DescriptorIterator { i: descriptor };
    let mut current_usage_page = 0u16;
    for item in descriptor {
        // trace!("item: {item:?}");
        match item.tag {
            Some(Tag::UsagePage) => {
                if let Ok(usage_page) = item.value.try_into() {
                    current_usage_page = u16::from_le_bytes(usage_page);
                }
            }

            Some(Tag::Usage) => {
                if current_usage_page == FIDO_USAGE_PAGE {
                    // 1 or 2 byte usage page; expect the current usage page to be FIDO
                    if item.value.len() == 1 && u16::from(item.value[0]) == FIDO_USAGE_U2FHID {
                        return true;
                    }

                    if let Ok(usage) = item.value.try_into() {
                        if u16::from_le_bytes(usage) == FIDO_USAGE_U2FHID {
                            return true;
                        }
                    }
                }

                if let Ok(usage) = item.value.try_into() {
                    // 4 byte usage page; doesn't matter what the current usage page is
                    let usage_and_page = u32::from_le_bytes(usage);
                    let usage_page = (usage_and_page >> 16) as u16;
                    let usage = (usage_and_page & 0xffff) as u16;

                    if usage_page == FIDO_USAGE_PAGE && usage == FIDO_USAGE_U2FHID {
                        return true;
                    }
                }
            }

            _ => continue,
        }
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! fido_descriptor_tests {
        ($($name:ident: $expected:expr, $value:expr;)*) => {
        $(
            #[test]
            fn $name() -> std::result::Result<(), Box<dyn std::error::Error>> {
                let _ = tracing_subscriber::fmt().try_init();

                let descriptor = hex::decode($value)?;
                assert_eq!($expected, is_fido_authenticator(&descriptor));
                Ok(())
            }
        )*
        }
    }

    fido_descriptor_tests! {
        // Used by Feitian and Token2; 2 byte usage page + 1 byte usage
        feitian_token2: true, "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0";

        feitian_otp: false, "05010906a101050719e029e71500250175019508810295017508810395057501050819012905910295017503910395067508150025650507190029658100090375089540b102c0";
        keyboard1: false, "05010906a101050719e029e71500250175019508810295017508810195037501050819012903910295057501910195067508150026ff00050719002aff008100c0";
        keyboard2: false, "0601000980a10185011981298315002501950375018102950175058101c0050c0901a1018503150025017501950819b529b809cd09e209e909ea81020a83010a8a010a92010a94010a21021a23022a250281020a26020a27020a2a029503810295058101c00600ff0901a1018502250115007501950b1af1002afb008102950175058101150026ff7f092075109501b102c0";
        mouse1: false, "05010902a1010901a100050919012908150025019508750181020600ff0940950275081581257f810205010938950181060930093116018026ff7f751095028106c0c0";
        mouse2: false, "0680ff0980a10185801a00382a0738150025019508750181028520092095017508b102858e098eb102c0";

        invalid_1_byte: false, "01";
        invalid_2_byte: false, "0201";
        invalid_4_byte: false, "02010203";
        invalid_long: false, "fe";
        invalid_long_usage_page: false, "0701020304";
    }
}
