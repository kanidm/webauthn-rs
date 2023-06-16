use crate::{ctap2::GetInfoResponse, transport::Token, ui::UiCallback};

pub trait CtapAuthenticatorVersion<'a, T: Token, U: UiCallback> {
    const VERSION: &'static str;
    fn new_with_info(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self;
}
