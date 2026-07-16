#[cfg_attr(feature = "ssr", path = "main_ssr.rs")]
#[cfg_attr(not(feature = "ssr"), path = "main_client.rs")]
mod main_;

pub use self::main_::main;
