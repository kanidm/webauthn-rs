use crate::ui::*;
#[cfg(feature = "qrcode")]
use qrcode::{render::unicode::Dense1x2, QrCode};
use std::io::{stderr, Write};

/// Basic CLI [UiCallback] implementation, available with `--features ui-cli`.
///
/// This gets input from `stdin` and sends messages to `stderr`.
///
/// This is only intended for testing, and doesn't implement much functionality
/// (like localization).
///
/// **Tip**: to get QR codes for `cable` authenticators, enable the `qrcode`
/// feature.
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

    fn processing(&self) {
        let mut stderr = stderr();
        writeln!(stderr, "Processing...").ok();
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        let mut stderr = stderr();
        writeln!(stderr, "Need {remaining_samples} more sample(s)").ok();
        if let Some(feedback) = feedback {
            writeln!(stderr, "Last impression was {feedback:?}").ok();
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
        println!("{url}");
    }

    fn dismiss_qr_code(&self) {
        println!("caBLE authenticator detected, connecting...");
    }

    fn cable_status_update(&self, state: CableState) {
        println!("caBLE status: {state:?}");
    }
}
