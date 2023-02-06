// use base64urlsafedata::Base64UrlSafeData;

use crate::prelude::*;

use std::fmt;

pub struct Authority {
    pub ca: x509::X509,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sname = self
            .ca
            .subject_name()
            .entries()
            .fold(String::new(), |mut acc, s| {
                acc.push_str(s.data().as_utf8().expect("invalid subject dn").as_ref());
                acc
            });

        f.debug_struct("Authority")
            .field("subject", &self.ca.subject_name())
            .finish()
    }
}
