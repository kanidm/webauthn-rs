use crypto_glue::x509;
use std::fmt;

pub struct Authority {
    pub ca: x509::Certificate,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("subject", &self.ca.tbs_certificate.subject)
            .finish()
    }
}
