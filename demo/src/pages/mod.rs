mod home;
mod login;
mod not_found;
mod register;

pub use self::{home::HomePage, login::LoginPage, not_found::NotFoundPage, register::RegisterPage};

fn is_username_valid(username: &str) -> bool {
    username.len() >= 3 && !username.contains(char::is_whitespace)
}
