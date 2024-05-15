use openssl::version::{number, version};

const OPENSSL_DOC: &str = "https://github.com/kanidm/webauthn-rs/blob/master/OpenSSL.md";

fn main() {
    // LibreSSL reports as OpenSSL v2 (which was skipped).
    #[allow(clippy::unusual_byte_groupings)]
    if number() < 0x2_00_00_00_0 {
        println!(
            r#"
Your version of OpenSSL is out of date, and not supported by this library.

Please upgrade to OpenSSL v3.0.0 or later.

More info: {OPENSSL_DOC}
OpenSSL version string: {}
"#,
            version(),
        );
        panic!("The installed version of OpenSSL is unusable.");
    }
}
