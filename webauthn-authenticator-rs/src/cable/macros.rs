#[macro_export]
#[cfg(feature = "cable-override-tunnel")]
macro_rules! pub_if_cable_override_tunnel {
    ($(#[$($meta:meta)*])* $ident:ident $($tokens:tt)*) => {
        $(#[$($meta)*])* pub $ident $($tokens)*
    };
}

#[macro_export]
#[cfg(not(feature = "cable-override-tunnel"))]
macro_rules! pub_if_cable_override_tunnel {
    ($(#[$($meta:meta)*])* $ident:ident $($tokens:tt)*) => {
        $(#[$($meta)*])* $ident $($tokens)*
    };
}
