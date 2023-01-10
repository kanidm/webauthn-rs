#[cfg(feature = "qrcode")]
use qrcode::{render::unicode::Dense1x2, QrCode};
use std::fmt::Debug;
use std::io::{stderr, Write};

use crate::{
    ctap2::EnrollSampleStatus,
    types::{CableRequestType, CableState},
};

pub trait UiCallback: Sync + Send + Debug {
    /// Prompts the user to enter their PIN.
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing or touching its button.
    ///
    /// This method will be called synchronously, and must not block.
    fn request_touch(&self);

    /// Provide the user feedback when they are enrolling fingerprints.
    ///
    /// This method will be called synchronously, and must not block.
    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    );

    /// Prompt the user to scan a QR code with their mobile device to start the
    /// caBLE linking process.
    ///
    /// This method will be called synchronously, and must not block.
    fn cable_qr_code(&self, request_type: CableRequestType, url: String);

    /// Dismiss a displayed QR code from the screen.
    ///
    /// This method will be called synchronously, and must not block.
    fn dismiss_qr_code(&self);

    fn cable_status_update(&self, state: CableState);
}

/// Basic CLI [UiCallback] implementation.
///
/// This gets input from `stdin` and sends messages to `stderr`.
///
/// This is only intended for testing, and doesn't implement much functionality (like localization).
#[derive(Debug)]
pub struct Cli {}

impl UiCallback for Cli {
    fn request_pin(&self) -> Option<String> {
        rpassword::prompt_password_stderr("Enter PIN: ").ok()
    }

    fn request_touch(&self) {
        let mut stderr = stderr();
        writeln!(stderr, "Touch the authenticator").ok();
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        let mut stderr = stderr();
        writeln!(stderr, "Need {} more sample(s)", remaining_samples).ok();
        if let Some(feedback) = feedback {
            writeln!(stderr, "Last impression was {:?}", feedback).ok();
        }
    }

    fn cable_qr_code(&self, request_type: CableRequestType, url: String) {
        match request_type {
            CableRequestType::DiscoverableMakeCredential | CableRequestType::MakeCredential => {
                println!("Scan the QR code with your mobile device to create a new credential with caBLE:");
            }
            CableRequestType::GetAssertion => {
                println!("Scan the QR code with your mobile device to sign in with caBLE:");
            }
        }
        println!("This feature requires Android with Google Play, or iOS 16 or later.");

        #[cfg(feature = "qrcode")]
        {
            let qr = QrCode::new(&url).expect("Could not create QR code");

            let code = qr
                .render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .build();

            println!("{}", code);
        }

        #[cfg(not(feature = "qrcode"))]
        {
            println!("QR code support not available in this build!")
        }
        println!("{}", url);
    }

    fn dismiss_qr_code(&self) {
        println!("caBLE authenticator detected, connecting...");
    }

    fn cable_status_update(&self, state: CableState) {
        println!("caBLE status: {:?}", state);
    }
}
