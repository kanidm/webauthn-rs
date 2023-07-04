//! Dependency stubs for documentation.
//!
//! This allows you to build the documentation for all features without actually
//! installing all of their depedencies.
//!
//! This isn't a complete set of stubs, only the types which are exposed across
//! method boundaries.
#[cfg(not(doc))]
compile_error!("Documentation stubs must only be included with #[cfg(doc)]");

#[cfg(not(feature = "mozilla"))]
pub mod authenticator {
    pub mod authenticatorservice {
        pub struct AuthenticatorService {}
    }
    pub struct StatusUpdate {}
}

#[cfg(not(feature = "nfc"))]
pub mod pcsc {
    pub struct Context {}
    pub enum Scope {}
    pub struct State {}
    pub struct Card {}
    pub struct ReaderState {}
}

#[cfg(not(any(feature = "ctap2", feature = "cable")))]
pub mod tokio {
    pub mod net {
        pub struct TcpStream {}
    }
    pub mod sync {
        pub mod mpsc {
            pub struct Sender<T> {}
            pub struct Receiver<T> {}
        }
    }
    pub mod time {
        pub async fn sleep(_: std::time::Duration) {}
    }
}

#[cfg(not(feature = "cable"))]
pub mod tokio_tungstenite {
    pub mod tungstenite {
        pub mod http {
            pub struct Uri {}
            pub mod uri {
                pub struct Builder {}
            }
        }
    }
    pub struct MaybeTlsStream<T> {}
    pub struct WebSocketStream<T> {}
}

#[cfg(not(any(feature = "bluetooth", feature = "cable")))]
pub mod btleplug {
    pub mod api {
        pub struct Central {}
        pub enum CentralEvent {}
        pub struct Characteristic {}
        pub struct Manager {}
        pub struct Peripheral {}
        pub struct ScanFilter {}
        pub enum WriteType {}
        pub mod bleuuid {
            pub const fn uuid_from_u16(_: u16) -> uuid::Uuid {
                uuid::Uuid::nil()
            }
        }
    }
    pub mod platform {
        pub struct Manager {}
        pub struct Peripheral {}
    }
}

#[cfg(not(feature = "crypto"))]
pub mod openssl {
    pub mod asn1 {}
    pub mod bn {
        pub struct BigNumContext {}
    }
    pub mod ec {
        pub struct EcKey<T> {}
        pub struct EcGroup {}
        pub struct EcKeyRef<T> {}
        pub struct EcPoint {}
        pub struct EcPointRef {}
        pub enum PointConversionForm {}
    }
    pub mod hash {
        pub struct MessageDigest {}
    }
    pub mod pkey {
        pub struct Id {}
        pub struct PKey<T> {}
        pub struct PKeyRef<T> {}
        pub struct Private {}
        pub struct Public {}
    }
    pub mod pkey_ctx {
        pub struct PkeyCtx {}
    }
    pub mod md {
        pub struct Md {}
    }
    pub mod nid {
        pub enum Nid {}
    }
    pub mod rand {
        pub fn rand_bytes() {
            unimplemented!()
        }
    }
    pub mod sha {
        pub struct Sha256 {}
    }
    pub mod sign {
        pub struct Signer {}
    }
    pub mod symm {
        pub fn decrypt_aead() {
            unimplemented!()
        }
        pub fn encrypt_aead() {
            unimplemented!()
        }
        pub struct Cipher {}
        pub struct Crypter {}
        pub enum Mode {}
    }
    pub mod x509 {
        pub mod extension {
            pub struct AuthorityKeyIdentifier {}
            pub struct BasicConstraints {}
            pub struct KeyUsage {}
            pub struct SubjectKeyIdentifier {}
        }
        pub struct X509 {}
        pub struct X509NameBuilder {}
        pub struct X509Ref {}
        pub struct X509ReqBuilder {}
    }
}

#[cfg(not(feature = "crypto"))]
pub mod webauthn_rs_core {
    pub mod proto {
        pub struct COSEEC2Key {}
        pub struct COSEKey {}
        pub enum COSEKeyType {}
        pub enum COSEKeyTypeId {}
        pub enum ECDSACurve {}
    }
}
