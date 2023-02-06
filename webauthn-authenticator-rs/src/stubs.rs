//! Dependency stubs for documentation.
//!
//! This allows you to build the documentation for all features without actually
//! installing all of their depedencies.
//!
//! This isn't a complete set of stubs, only the types which are exposed across
//! method boundaries.
#[cfg(not(doc))]
compile_error!("Documentation stubs must only be included with #[cfg(doc)]");

#[cfg(not(feature = "u2fhid"))]
pub mod authenticator {
    pub mod authenticatorservice {
        pub struct AuthenticatorService {}
    }
    pub struct StatusUpdate {}
}

#[cfg(not(feature = "usb"))]
pub mod hidapi {
    pub struct HidApi {}
    pub struct HidDevice {}
}

#[cfg(not(feature = "nfc"))]
pub mod pcsc {
    pub struct Context {}
    pub enum Scope {}
    pub struct State {}
    pub struct Card {}
    pub struct ReaderState {}
}

#[cfg(not(feature = "cable"))]
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

#[cfg(not(feature = "btleplug"))]
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
