//! Helpers for working with Windows native types.
use crate::error::WebauthnCError;
use std::marker::PhantomData;
use std::ops::Deref;
use std::pin::Pin;
use windows::core::PCWSTR;

/// Smart pointer type to automatically `free()` bare pointers we got from
/// Windows' API when dropped.
pub struct WinPtr<'a, T: 'a> {
    free: unsafe fn(*const T) -> (),
    ptr: *const T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> WinPtr<'a, T> {
    /// Creates a wrapper around a `*const T` pointer which automatically calls
    /// the `free` function when dropped.
    ///
    /// Returns `None` if `ptr` is null.
    ///
    /// Unsafe if `ptr` is unaligned or does not point to a `T`.
    pub unsafe fn new(ptr: *const T, free: unsafe fn(*const T) -> ()) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            // trace!("new_ptr: r={:?}", ptr);
            Some(Self {
                free,
                ptr,
                phantom: PhantomData,
            })
        }
    }
}

impl<'a, T> Deref for WinPtr<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &(*self.ptr) }
    }
}

impl<'a, T> Drop for WinPtr<'a, T> {
    fn drop(&mut self) {
        // trace!("free_ptr: r={:?}", self.ptr);
        unsafe { (self.free)(self.ptr) }
    }
}

/// Wrapper for a `webauthn-authenticator-rs` type (`T`) to convert it to a
/// Windows WebAuthn API type (`NativeType`).
pub trait WinWrapper<T> {
    /// Windows equivalent type for `T`
    type NativeType;
    /// Converts a `webauthn-authenticator-rs` type to a Windows type
    fn new(v: T) -> Result<Pin<Box<Self>>, WebauthnCError>
    where
        Self: Sized;
    /// Returns a pointer to the Windows equivalent type
    fn native_ptr(&self) -> &Self::NativeType;
}

pub trait StringEqualPtr {
    unsafe fn equals_pcwstr(&self, other: PCWSTR) -> bool;
    fn equals_wide(&self, other: &[u16]) -> bool;
}

impl StringEqualPtr for String {
    unsafe fn equals_pcwstr(&self, other: PCWSTR) -> bool {
        self.encode_utf16().eq(other.as_wide().iter().copied())
    }

    fn equals_wide(&self, other: &[u16]) -> bool {
        self.encode_utf16().eq(other.iter().copied())
    }
}
