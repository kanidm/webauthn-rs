//! GUI code for Windows WebAuthn API.
//!
//! Windows WebAuthn API needs a [HWND] parameter to know where to attach its
//! UI to, but the `webauthn-authenticator-rs` API doesn't know anything about
//! [HWND]s.
//!
//! Also, when running in a console application, getting a _functional_ [HWND]
//! is a broken mess, because [GetConsoleWindow] only works properly for
//! "classical" `cmd.exe` prompts: Windows Terminal
//! [has focus issues, even though the issue is "closed"][terminal], and VS
//! Code [also has z-order issues][vscode]. Both make for an awful experience,
//! and [the normal work-arounds][hack] don't work when a console app can't
//! set the window title verbatim (such as in VS Code).
//!
//! There is some prior art in [windows-fido-bridge], but this ended up with
//! a distinct design that doesn't hard-code work-arounds for single apps.
//!
//! **Warning:** This hasn't yet been tested in a Windows GUI application,
//! and is subject to change based on user feedback.
//!
//! [Window] creates a 1x1 pixel window for Windows WebAuthn API to use:
//!
//! * If there is a [current foreground window][GetForegroundWindow],
//!   our window is a child tool window, and is centred over it. This gives
//!   focus without intervention, proper z-ordering, and handles DPI scaling.
//!
//! * If there is no current foreground window, our window is a pop-up layered
//!   window, centered on the primary screen, and then made invisible.
//!
//! After that, the Windows WebAuthn API will centre its dialog on top of our
//! [Window] as a child, automatically taking focus.
//!
//! [windows-fido-bridge]: https://github.com/mgbowen/windows-fido-bridge/blob/master/src/win32_middleware_common/src/window.cpp
//! [GetConsoleWindow]: https://learn.microsoft.com/en-us/windows/console/getconsolewindow
//! [hack]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/obtain-console-window-handle
//! [terminal]: https://github.com/microsoft/terminal/issues/2988
//! [vscode]: https://github.com/microsoft/vscode/issues/42356
use crate::error::WebauthnCError;
use std::{
    ffi::c_void,
    mem::size_of,
    sync::{mpsc::sync_channel, Once},
    thread,
};
use windows::{
    core::{HSTRING, PCWSTR},
    w,
    Win32::{
        Foundation::{GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::{
            Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS},
            Gdi::{GetSysColorBrush, COLOR_WINDOW},
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetForegroundWindow,
            GetMessageW, GetSystemMetrics, LoadCursorW, LoadIconW, MoveWindow, PostMessageW,
            PostQuitMessage, RegisterClassExW, SetForegroundWindow, SetLayeredWindowAttributes,
            TranslateMessage, CS_HREDRAW, CS_OWNDC, CS_VREDRAW, CW_USEDEFAULT, IDC_ARROW,
            IDI_APPLICATION, LWA_ALPHA, MSG, SM_CXSCREEN, SM_CYSCREEN, WM_CLOSE, WM_DESTROY,
            WM_QUIT, WNDCLASSEXW, WS_CHILD, WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
            WS_POPUPWINDOW, WS_VISIBLE,
        },
    },
};

/// [WndProc callback handler][wndproc] for our [WINDOW_CLASS].
///
/// [wndproc]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-wndproc
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CLOSE => {
            DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Window class for our [Window].
const WINDOW_CLASS: &HSTRING = w!("webauthn-authenticator-rs");

/// Gets a module handle for the current process and registers
/// [WINDOW_CLASS] on first run.
unsafe fn get_module_handle() -> HINSTANCE {
    static INIT: Once = Once::new();
    static mut MODULE_HANDLE: HINSTANCE = HINSTANCE(0);

    INIT.call_once(|| {
        MODULE_HANDLE = GetModuleHandleW(PCWSTR::null()).expect("GetModuleHandleW");

        let icon = LoadIconW(None, IDI_APPLICATION).expect("LoadIconW");
        let wnd_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: MODULE_HANDLE,
            hIcon: icon,
            hCursor: LoadCursorW(None, IDC_ARROW).expect("LoadCursorW"),
            hbrBackground: GetSysColorBrush(COLOR_WINDOW),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: WINDOW_CLASS.into(),
            hIconSm: icon,
        };

        RegisterClassExW(&wnd_class);
    });

    MODULE_HANDLE
}

/// Window to act as a parent for Windows WebAuthn API.
pub struct Window {
    hwnd: HWND,
}

impl Window {
    /// Creates a new window and spawns an event loop in the background.
    ///
    /// The window will persist until dropped.
    pub fn new() -> Result<Self, WebauthnCError> {
        let (sender, receiver) = sync_channel::<HWND>(0);

        thread::spawn(move || {
            // trace!("spawned background");
            // let parent = HWND(0);
            let parent = unsafe { GetForegroundWindow() };
            let hwnd = unsafe {
                let hinstance = get_module_handle();
                let (style, ex_style) = if parent != HWND(0) {
                    // Parent: act like a child tool-window, so it doesn't
                    // appear in alt-tab, but still gets focus.
                    (WS_CHILD, WS_EX_TOOLWINDOW)
                } else {
                    // No parent: act like a normal window so we can be alt-tabbed.
                    (WS_POPUPWINDOW, WS_EX_LAYERED)
                };

                // CreateWindowEx is virtualised for DPI scaling, so we'll need
                // to MoveWindow later.
                CreateWindowExW(
                    WS_EX_TOPMOST | ex_style,
                    WINDOW_CLASS,
                    WINDOW_CLASS,
                    style | WS_VISIBLE,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    1,
                    1,
                    parent,
                    None,
                    hinstance,
                    None,
                )
            };
            // trace!(?hwnd);

            if hwnd == HWND(0) {
                let e = unsafe { GetLastError() };
                error!("window not created, {:?}", e);
                sender.send(hwnd).ok();
                return;
            }

            // Focus, foreground and reposition our window (if needed).
            unsafe {
                if !SetForegroundWindow(hwnd).as_bool() {
                    trace!("Tried to set the foreground window, but the request was denied.");
                }

                if parent == HWND(0) {
                    // When we have an un-parented window, make it invisible
                    // and put it in the centre of the primary screen.
                    SetLayeredWindowAttributes(hwnd, None, 0, LWA_ALPHA);
                    Some((
                        GetSystemMetrics(SM_CXSCREEN) / 2,
                        GetSystemMetrics(SM_CYSCREEN) / 2,
                    ))
                } else {
                    // When we have a parent window, MoveWindow is relative to the position
                    // of the parent.
                    get_window_rect(parent).map(half_size)
                }
                .map(|(x, y)| MoveWindow(hwnd, x, y, 1, 1, true));
            }

            // Now we can tell the main thread that the window is ready.
            if sender.send(hwnd).is_err() {
                return;
            }

            // Windows event loop
            let mut msg: MSG = Default::default();
            loop {
                let res: bool = unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool();
                if !res {
                    break;
                }

                if msg.message == WM_QUIT {
                    unsafe {
                        PostQuitMessage(msg.wParam.0 as i32);
                    }
                }
                // trace!(?msg);
                unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            // trace!("background stopped");
        });

        let hwnd = receiver.recv();
        match hwnd {
            Ok(HWND(0)) | Err(_) => Err(WebauthnCError::Internal),
            Ok(hwnd) => Ok(Self { hwnd }),
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // trace!("dropping window");
        unsafe {
            PostMessageW(self.hwnd, WM_CLOSE, None, None);
        }
    }
}

impl From<&Window> for HWND {
    fn from(w: &Window) -> HWND {
        w.hwnd
    }
}

/// Gets the position of a window in "true" pixels (not virtualised for DPI scaling).
fn get_window_rect(hwnd: HWND) -> Option<RECT> {
    let mut r: RECT = Default::default();
    // GetClientRect and GetWindowRect are virtualised for DPI scaling,
    // but MoveWindow is not, so we need DWMWA_EXTENDED_FRAME_BOUNDS.
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut r as *mut _ as *mut c_void,
            size_of::<RECT>() as u32,
        )
    }
    .is_ok()
    .then_some(r)
}

/// Returns half the size of the [RECT] as `(width, height)`.
const fn half_size(rect: RECT) -> (i32, i32) {
    (
        ((rect.right - rect.left) / 2),
        ((rect.bottom - rect.top) / 2),
    )
}
