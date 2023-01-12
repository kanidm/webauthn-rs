use openssl::{error::ErrorStack, md::Md, pkey::Id, pkey_ctx::PkeyCtx, version::version};

/// Performs HKDF-SHA-256; copy of version from `./src/crypto.rs`.
fn hkdf_sha_256<const N: usize>(salt: &[u8], ikm: &[u8]) -> Result<[u8; N], ErrorStack> {
    let mut output = [0; N];
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.derive(Some(&mut output)).unwrap();
    Ok(output)
}

fn main() {
    // Having a working hkdf_sha_256 implementation is essential for some parts
    // of the library functioning. We should fail early if something goes wrong.
    //
    // Empty IKM fails (with malloc error) unless you have OpenSSL 3.0.0 to pull
    // in this patch: https://github.com/openssl/openssl/pull/12826
    //
    // caBLE uses empty IKM.
    let salt = [
        0x30, 0x7a, 0x70, 0x6e, 0x63, 0x38, 0x2e, 0x8e, 0x9d, 0x46, 0xcc, 0xdb, 0xc, 0xeb, 0xed,
        0x5c, 0x2b, 0x19, 0x28, 0xc5, 0xae, 0x2d, 0xee, 0x63, 0x52, 0xe1, 0x30, 0xac, 0xe1, 0xf7,
        0x4f, 0x44,
    ];
    let expected = [
        0x1f, 0xba, 0x3c, 0xce, 0x17, 0x62, 0x2c, 0x68, 0x26, 0x8d, 0x9f, 0x75, 0xb5, 0xa8, 0xa3,
        0x35, 0x1b, 0x51, 0x7f, 0x9, 0x6f, 0xb5, 0xe2, 0x94, 0x94, 0x1a, 0xf7, 0xe3, 0xa6, 0xa8,
        0xd6, 0xe1, 0xe3, 0x4f, 0x1a, 0xa3, 0x74, 0x72, 0x38, 0xc0, 0x4d, 0x3b, 0xd2, 0x5e, 0x7,
        0xef, 0x1b, 0x35, 0xfe, 0xf3, 0x59, 0x0, 0xd, 0x75, 0x56, 0x15, 0xcd, 0x85, 0xbe, 0x27,
        0xcf, 0xc8, 0x7, 0xd1,
    ];

    let r: Result<[u8; 64], _> = hkdf_sha_256(&salt, &[]);
    if !matches!(r, Ok(actual) if actual == expected) {
        println!(
            r#"
Your version of OpenSSL did not perform HKDF-SHA-256 with a zero-length
secret correctly, because of an OpenSSL bug. This issue will cause
webauthn-authenticator-rs to malfunction.

Please upgrade to OpenSSL v3.0.0 or later.
"#
        );
        match r {
            Ok(actual) => {
                println!("Diagnostic: Result mismatched.");
                println!("Expected: {:02x?}", expected);
                println!("Actual  : {:02x?}", actual);
            }
            Err(e) => {
                println!("Diagnostic: OpenSSL error: {:?}", e);
            }
        }
        println!();
        println!("OpenSSL version string: {}", version());
        panic!("The installed version of OpenSSL is unusable.");
    }
}
