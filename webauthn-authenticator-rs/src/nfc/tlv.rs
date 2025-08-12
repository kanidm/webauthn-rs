//! [CompactTlv] is an [Iterator]-based Compact-TLV parser.

/// An [Iterator]-based Compact-TLV parser.
pub(crate) struct CompactTlv<'a> {
    b: &'a [u8],
}

impl CompactTlv<'_> {
    /// Parses a Compact-TLV structure in the given slice.
    pub fn new(tlv: &[u8]) -> CompactTlv<'_> {
        // Skip null bytes at the start
        let mut i = 0;
        loop {
            if i >= tlv.len() || tlv[i] != 0 {
                break;
            }
            i += 1;
        }

        CompactTlv { b: &tlv[i..] }
    }
}

impl<'a> Iterator for CompactTlv<'a> {
    /// A Compact-TLV item, a tuple of `tag, value`.
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.b.is_empty() {
            return None;
        }
        let tl = self.b[0];
        let tag = tl >> 4;
        let len: usize = (tl & 0xf).into();

        if self.b.len() < len + 1 {
            // The length of the tag extends out of bounds
            return None;
        }
        let v = &self.b[1..len + 1];

        // Slide the buffer along
        self.b = &self.b[len + 1..];
        Some((tag, v))
    }
}
