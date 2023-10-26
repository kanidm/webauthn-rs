//! [BerTlvParser] is an [Iterator]-based BER-TLV parser.

/// An [Iterator]-based Compact-TLV parser.
pub(crate) struct BerTlvParser<'a> {
    b: &'a [u8],
}

impl BerTlvParser<'_> {
    /// Parses a BER-TLV structure in the given slice.
    pub fn new(tlv: &[u8]) -> BerTlvParser {
        // Skip null bytes at the start
        let mut i = 0;
        loop {
            if i >= tlv.len() || tlv[i] != 0 {
                break;
            }
            i += 1;
        }

        BerTlvParser { b: &tlv[i..] }
    }

    #[inline]
    fn brick(&mut self) {
        self.b = &self.b[0..0];
    }

    fn stop_if_empty(&self) -> Option<()> {
        if self.b.is_empty() {
            None
        } else {
            Some(())
        }
    }

    fn stop_and_brick_if_less_than(&mut self, bytes: usize) -> Option<()> {
        if self.b.len() < bytes {
            error!("bricked: less than {bytes} bytes: {}", self.b.len());
            self.brick();
            None
        } else {
            Some(())
        }
    }
}

impl<'a> Iterator for BerTlvParser<'a> {
    /// A BER-TLV item, a tuple of `class, tag, value`.
    type Item = (u8, u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.stop_if_empty()?;

        // 5.2.2.1: BER-TLV tag fields
        let class = self.b[0] >> 5;
        let mut tag = u16::from(self.b[0] & 0x1f);
        // trace!(?class, ?tag);
        self.b = &self.b[1..];
        if tag == 0x1f {
            self.stop_if_empty()?;
            // 0b???1_1111 = 2 or 3 byte tag value
            tag = u16::from(self.b[0]);
            self.b = &self.b[1..];

            // 2 byte tag value as 0b0???_???? (31..=127)
            // 3 byte tag value as 0b1???_???? 0b0???_???? (128..=16383)
            if tag & 0x80 == 0x80 {
                self.stop_if_empty()?;

                tag = (tag & 0x7f) << 7;
                tag |= u16::from(self.b[0]) & 0x7f;
                self.b = &self.b[1..];
            }
        }

        // 5.2.2.2 BER-TLV length fields
        self.stop_if_empty()?;
        let len = self.b[0];
        self.b = &self.b[1..];

        let len = match len {
            0..=0x7f => u32::from(len),

            0x80 => {
                error!("indefinite length not supported");
                self.brick();
                return None;
            }

            0x81 => {
                self.stop_if_empty()?;
                let len = u32::from(self.b[0]);
                self.b = &self.b[1..];
                len
            }

            0x82 => {
                self.stop_and_brick_if_less_than(2);
                let len = u32::from(u16::from_be_bytes(self.b[..2].try_into().ok()?));
                self.b = &self.b[2..];
                len
            }

            0x83 => {
                self.stop_and_brick_if_less_than(3)?;
                let mut buf = [0; 4];
                buf[1..].copy_from_slice(&self.b[..3]);
                let len = u32::from_be_bytes(buf);
                self.b = &self.b[3..];
                len
            }

            0x84 => {
                self.stop_and_brick_if_less_than(4)?;
                let len = u32::from_be_bytes(self.b[..4].try_into().ok()?);
                self.b = &self.b[4..];
                len
            }

            0x85..=0xff => {
                error!("invalid BER-TLV length field length: {len:#x}");
                self.brick();
                return None;
            }
        };
        // info!(?len);

        let len = len as usize;
        self.stop_and_brick_if_less_than(len)?;
        let v = &self.b[..len];
        self.b = &self.b[len..];
        Some((class, tag, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_tlv_parser(expected: &[(u8, u16, &[u8])], p: BerTlvParser<'_>) {
        let mut i = 0;
        for (actual_cls, actual_tag, actual_val) in p {
            let (expected_cls, expected_tag, expected_val) = expected[i];
            assert_eq!(expected_cls, actual_cls, "cls mismatch at {i}");
            assert_eq!(expected_tag, actual_tag, "tag mismatch at {i}");
            assert_eq!(
                expected_val, actual_val,
                "val mismatch at {i} (tag={expected_tag})"
            );
            i += 1;
        }
        assert_eq!(expected.len(), i);
    }

    #[test]
    fn yubico_security_key_c_nfc() {
        let _ = tracing_subscriber::fmt().try_init();

        let v = hex::decode(concat!(
            "28",     // length byte, not TLV
            "0102",   // cls=0, tag=1, len=2
            "0202",   //
            "0302",   // cls=0, tag=3, len=2
            "0200",   //
            "0401",   // cls=0, tag=4, len=1
            "43",     //
            "0503",   // cls=0, tag=5, len=3
            "050403", //
            "0602",   // cls=0, tag=6, len=2
            "0000",   //
            "0701",   // cls=0, tag=7, len=1
            "0f",     //
            "0801",   // cls=0, tag=8, len=1
            "00",     //
            "0d02",   // cls=0, tag=13, len=2
            "0206",   //
            "0e02",   // cls=0, tag=14, len=2
            "0200",   //
            "0a01",   // cls=0, tag=10, len=1
            "00",     //
            "0f01",   // cls=0, tag=15, len=1
            "00",     //
        ))
        .unwrap();
        let expected: [(u8, u16, &[u8]); 11] = [
            (0, 1, b"\x02\x02"),
            (0, 3, b"\x02\0"),
            (0, 4, b"\x43"),
            (0, 5, b"\x05\x04\x03"),
            (0, 6, b"\0\0"),
            (0, 7, b"\x0f"),
            (0, 8, b"\0"),
            (0, 13, b"\x02\x06"),
            (0, 14, b"\x02\0"),
            (0, 10, b"\0"),
            (0, 15, b"\0"),
        ];

        let p = BerTlvParser::new(&v[1..]);
        assert_tlv_parser(expected.as_slice(), p);
    }

    #[test]
    fn yubikey_5c() {
        let _ = tracing_subscriber::fmt().try_init();

        let v = hex::decode(concat!(
            "23",       // length byte, not TLV
            "0102",     // cls=0, tag=1, len=2
            "023f",     //
            "0302",     // cls=0, tag=3, len=2
            "0218",     //
            "0204",     // cls=0, tag=2, len=4
            "cafe1234", //
            "0401",     // cls=0, tag=4, len=1
            "03",       //
            "0503",     // cls=0, tag=5, len=3
            "050102",   //
            "0602",     // cls=0, tag=6, len=2
            "0000",     //
            "0701",     // cls=0, tag=7, len=1
            "0f",       //
            "0801",     // cls=0, tag=8, len=1
            "00",       //
            "0a01",     // cls=0, tag=10, len=1
            "00",       //
        ))
        .unwrap();
        let expected: [(u8, u16, &[u8]); 9] = [
            (0, 1, b"\x02\x3f"),
            (0, 3, b"\x02\x18"),
            (0, 2, b"\xca\xfe\x12\x34"),
            (0, 4, b"\x03"),
            (0, 5, b"\x05\x01\x02"),
            (0, 6, b"\0\0"),
            (0, 7, b"\x0f"),
            (0, 8, b"\0"),
            (0, 10, b"\0"),
        ];

        let p = BerTlvParser::new(&v[1..]);
        assert_tlv_parser(expected.as_slice(), p);
    }
}
