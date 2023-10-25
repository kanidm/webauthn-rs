//! [NFCTransport] communicates with a FIDO authenticator using the PC/SC API.
//!
//! ## Transport
//!
//! The CTAP specifications describe an "ISO 7816, ISO 14443 and Near Field
//! Communication" transport, but PC/SC supports both contact (ISO 7816-3) and
//! contactless (ISO 14443 and others) smart card interfaces.
//!
//! For consistency with other implementations (Windows) and the existing
//! WebAuthn specification, this library calls them all "NFC", even though
//! interface entirely operates on an ISO 7816 level. This module should work
//! with FIDO tokens regardless of physical transport.
//!
//! Some tokens (like Yubikey) provide a USB CCID (smart card) interface for
//! other applets (such as PGP and PIV), but do not typically expose the FIDO
//! applet over the same interface due to the possibility of websites bypassing
//! the WebAuthn API on ChromeOS by using WebUSB[^1].
//!
//! [^1]: [ChromeOS' PC/SC implementation][2] is pcsclite running in a browser
//! extension, which accesses USB CCID interfaces via WebUSB. By comparison,
//! other platforms' PC/SC implementations take exclusive control of USB CCID
//! devices outside of the browser, preventing access from WebUSB.
//!
//! [2]: https://github.com/GoogleChromeLabs/chromeos_smart_card_connector/blob/main/docs/index-developer.md
//!
//! ## Windows
//!
//! ### Windows 10 WebAuthn API
//!
//! Windows' WebAuthn API (on Windows 10 build 1903 and later) blocks
//! non-Administrator access to **all** NFC FIDO tokens, throwing an error
//! whenever an application attempts to select the FIDO applet, even if it is
//! not present!
//!
//! Use [Win10][crate::win10::Win10] (available with the `win10` feature) on
//! Windows instead.
//!
//! ### Smart card service
//!
//! By default, Windows runs the [Smart Card service][3] (`SCardSvr`) in
//! "Manual (Triggered)" start-up mode. Rather than starting the service on
//! boot, Windows will wait for an application to use the PC/SC API.
//!
//! However, Windows *does not* automatically start `SCardSvr` if:
//!
//! * there has *never* been a smart card reader (or other CCID interface, such
//!   as a Yubikey) connected to the PC
//!
//! * the user has explicitly disabled the service (in `services.msc`)
//!
//! Instead, Windows returns an error ([`NoService`][4]) when establishing a
//! context (in [`NFCTransport::new()`]).
//!
//! [`AnyTransport`] will ignore unavailability of `SCardSvr`, as it is presumed
//! that PC/SC is one of many potentially-available transports.
//!
//! [3]: https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-smart-cards-for-windows-service
//! [4]: pcsc::Error::NoService
use crate::ctap2::commands::to_short_apdus;
use crate::error::{CtapError, WebauthnCError};
use crate::ui::UiCallback;

#[cfg(doc)]
use crate::stubs::*;

use async_trait::async_trait;
use futures::executor::block_on;
use futures::{stream::BoxStream, Stream};
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;

use pcsc::*;
use std::ffi::{CStr, CString};
use std::fmt;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;
use webauthn_rs_proto::AuthenticatorTransport;

mod atr;
mod tlv;

pub use self::atr::*;
use crate::transport::iso7816::*;
use crate::transport::*;

/// Version string for a token which supports CTAP v1 / U2F (`U2F_V2`)
pub const APPLET_U2F_V2: [u8; 6] = [0x55, 0x32, 0x46, 0x5f, 0x56, 0x32];
/// Version string for a token which only supports CTAP v2 (`FIDO_2_0`)
pub const APPLET_FIDO_2_0: [u8; 8] = [0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30];
/// ISO 7816 FIDO applet name
pub const APPLET_DF: [u8; 8] = [
    /* RID */ 0xA0, 0x00, 0x00, 0x06, 0x47, /* PIX */ 0x2F, 0x00, 0x01,
];

/// List of strings, which if they appear in a PC/SC card reader's name,
/// indicate we should ignore it.
///
/// **See:** [`ignored_reader()`]
const IGNORED_READERS: [&str; 3] = [
    // Trussed (used by Nitrokey 3 and SoloKeys Solo 2) expose a USB CCID
    // interface which allows U2F applet selection, but then returns 0x6985
    // (conditions of use not satisfied) to every command sent thereafter:
    // https://github.com/trussed-dev/fido-authenticator/blob/7bd0c3bc5105a122fa11d9b354457746f391c4fb/src/dispatch/apdu.rs#L44-L48
    // https://github.com/trussed-dev/fido-authenticator/issues/38
    "Nitrokey", "SoloKey",
    // YubiKey exposes a CCID interface when OpenGPG or PIV support is enabled,
    // and this interface doesn't support FIDO.
    "YubiKey",
];

/// Is the PC/SC card reader one which should be ignored?
///
/// Some USB security keys expose a USB CCID interface, which either don't
/// expose a FIDO applet (as recommended by [non-public FIDO documentation][0])
/// or is unusable.
///
/// Don't waste time enumerating these!
///
/// If `reader_name` does not contain valid UTF-8, this returns `false`.
///
/// [0]: https://github.com/w3c/webauthn/issues/1835#issuecomment-1382660217
fn ignored_reader(reader_name: &CStr) -> bool {
    let reader_name = match reader_name.as_ref().to_str() {
        Ok(r) => r,
        Err(e) => {
            error!("could not convert {reader_name:?} to UTF-8: {e:?}");
            return false;
        }
    };

    let r = IGNORED_READERS.iter().any(|i| reader_name.contains(i));

    #[cfg(nfc_allow_ignored_readers)]
    if r {
        warn!("allowing ignored reader: {reader_name:?}");
        return false;
    }

    r
}

struct NFCDeviceWatcher {
    stream: ReceiverStream<TokenEvent<NFCCard>>,
}

impl NFCDeviceWatcher {
    fn new(ctx: Context) -> Self {
        let (tx, rx) = mpsc::channel(16);
        let stream = ReceiverStream::from(rx);

        spawn_blocking(move || {
            let mut enumeration_complete = false;
            let mut reader_states: Vec<ReaderState> =
                vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];

            'main: while !tx.is_closed() {
                // trace!(
                //     "{} known reader(s), pruning ignored readers",
                //     reader_states.len()
                // );

                // Remove all disconnected readers
                reader_states.retain(|state| {
                    !state
                        .event_state()
                        .intersects(State::UNKNOWN | State::IGNORE)
                });

                // trace!("{} reader(s) remain after pruning", reader_states.len());

                // Get a list of readers right now
                let readers = ctx.list_readers_owned()?;
                // trace!(
                //     "{} reader(s) currently connected: {:?}",
                //     readers.len(),
                //     readers
                // );

                if readers.is_empty() && !enumeration_complete {
                    // When there are no real readers connected (ie: other than
                    // PNP_NOTIFICATION), get_status_change() waits for either
                    // a reader to be connected, or timeout (1 second)... which
                    // is quite slow.
                    //
                    // When there are real reader(s), get_status_change
                    // immediately reports status change(s) for anything in the
                    // UNAWARE state.
                    enumeration_complete = true;
                    if tx.blocking_send(TokenEvent::EnumerationComplete).is_err() {
                        // Channel lost!
                        break 'main;
                    }
                }

                // Add any new readers to the list
                for reader_name in readers {
                    if !reader_states
                        .iter()
                        .any(|s| s.name() == reader_name.as_ref())
                    {
                        // We still need to keep track of ignored readers, so
                        // that we don't get spurious PNP_NOTIFICATION events
                        // for them.
                        trace!(
                            "New reader: {reader_name:?} {}",
                            if ignored_reader(&reader_name) {
                                "(ignored)"
                            } else {
                                ""
                            }
                        );
                        reader_states.push(ReaderState::new(reader_name, State::UNAWARE));
                    }
                }

                // Update view of current states
                // trace!("Updating {} reader states", reader_states.len());
                for state in &mut reader_states {
                    state.sync_current_state();
                }

                // Wait for further changes...
                let r = ctx.get_status_change(Duration::from_secs(1), &mut reader_states);

                if let Err(e) = r {
                    use pcsc::Error::*;
                    match e {
                        Timeout | UnknownReader => {
                            continue;
                        }

                        e => {
                            error!("while watching for PC/SC status changes: {e:?}");
                            r?;
                        }
                    }
                }

                // trace!("Updated reader states");
                let mut tasks = Vec::new();
                for state in &reader_states {
                    if state.name() == PNP_NOTIFICATION()
                        || !state.event_state().contains(State::CHANGED)
                        || ignored_reader(state.name())
                    {
                        continue;
                    }
                    trace!(
                        "Reader {:?} current_state: {:?}, event_state: {:?}",
                        state.name(),
                        state.current_state(),
                        state.event_state()
                    );

                    if state
                        .event_state()
                        .intersects(State::INUSE | State::EXCLUSIVE)
                    {
                        // TODO: The card could have been captured by something
                        // else, and we try again later.
                        trace!("ignoring in-use card");
                        continue;
                    }

                    if state.event_state().contains(State::PRESENT)
                        && !state.current_state().contains(State::PRESENT)
                    {
                        if let Ok(mut card) = NFCCard::new(&ctx, state.name(), state.atr()) {
                            let tx = tx.clone();
                            tasks.push(tokio::spawn(async move {
                                match card.init().await {
                                    Ok(()) => {
                                        let _ = tx.send(TokenEvent::Added(card)).await;
                                    }
                                    Err(e) => {
                                        error!("initialising card: {e:?}");
                                    }
                                };
                            }));
                        }
                    } else if state.event_state().contains(State::EMPTY)
                        && !state.current_state().contains(State::EMPTY)
                    {
                        if tx
                            .blocking_send(TokenEvent::Removed(state.name().to_owned()))
                            .is_err()
                        {
                            // Channel lost!
                            break 'main;
                        }
                    } else {
                        // Unhandled state transition
                    }
                }

                if !enumeration_complete {
                    // This condition is hit when there was at least one real
                    // reader connected on the first loop (which was in the
                    // UNAWARE state).
                    enumeration_complete = true;

                    // Wait for outstanding tasks which could signal "added"
                    // before EnumerationCompleted.
                    for task in tasks {
                        let _ = block_on(task);
                    }

                    if tx.blocking_send(TokenEvent::EnumerationComplete).is_err() {
                        // Channel lost!
                        break 'main;
                    }
                }
            }

            Ok::<(), WebauthnCError>(())
        });

        Self { stream }
    }
}

impl Stream for NFCDeviceWatcher {
    type Item = TokenEvent<NFCCard>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        ReceiverStream::poll_next(Pin::new(&mut Pin::get_mut(self).stream), cx)
    }
}

/// Wrapper for PC/SC context
pub struct NFCTransport {
    ctx: Context,
}

// Connection to a single NFC card
pub struct NFCCard {
    card: Mutex<Card>,
    reader_name: CString,
    pub atr: Atr,
    initialised: bool,
}

impl fmt::Debug for NFCTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCTransport").finish()
    }
}

impl fmt::Debug for NFCCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCCard")
            .field("reader_name", &self.reader_name)
            .field("atr", &self.atr)
            .field("initialised", &self.initialised)
            .finish()
    }
}

impl NFCTransport {
    /// Creates a new [NFCTransport] instance in a given [Scope].
    ///
    /// Example:
    ///
    /// ```no_run
    /// # #[cfg(feature = "nfc")]
    /// use pcsc::Scope;
    /// # #[cfg(feature = "nfc")]
    /// use webauthn_authenticator_rs::nfc::NFCTransport;
    ///
    /// # #[cfg(feature = "nfc")]
    /// let reader = NFCTransport::new(Scope::User);
    /// // TODO: Handle errors
    /// ```
    ///
    /// This returns an error [if the smart card service is unavailable][0].
    ///
    /// [0]: crate::nfc#smart-card-service
    pub fn new(scope: Scope) -> Result<Self, WebauthnCError> {
        Ok(NFCTransport {
            ctx: Context::establish(scope).map_err(WebauthnCError::PcscError)?,
        })
    }
}

#[async_trait]
impl<'b> Transport<'b> for NFCTransport {
    type Token = NFCCard;

    async fn watch(&self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError> {
        let watcher = NFCDeviceWatcher::new(self.ctx.clone());

        Ok(Box::pin(watcher))
    }

    async fn tokens(&self) -> Result<Vec<Self::Token>, WebauthnCError> {
        let mut r = Vec::new();
        {
            let readers = self.ctx.list_readers_owned()?;
            let mut reader_states: Vec<ReaderState> = readers
                .into_iter()
                .map(|n| ReaderState::new(n, State::UNAWARE))
                .collect();
            self.ctx
                .get_status_change(Duration::from_secs(1), &mut reader_states)?;

            for state in reader_states.iter() {
                if !state.event_state().contains(State::PRESENT) {
                    continue;
                }

                let c = match NFCCard::new(&self.ctx, state.name(), state.atr()) {
                    Err(_) => continue,
                    Ok(c) => c,
                };

                r.push(c);
            }
        }

        let mut i = 0;
        while i < r.len() {
            match r[i].init().await {
                Err(e) => {
                    error!("init card: {e:?}");
                    r.remove(i);
                }
                Ok(()) => {
                    i += 1;
                }
            }
        }

        Ok(r)
    }
}

/// Transmits a single ISO 7816-4 APDU to the card.
fn transmit(
    card: &Card,
    request: &ISO7816RequestAPDU,
    form: &ISO7816LengthForm,
) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
    let req = request.to_bytes(form).map_err(|e| {
        error!("Failed to build APDU command: {:?}", e);
        WebauthnCError::ApduConstruction
    })?;
    let mut resp = vec![0; MAX_BUFFER_SIZE_EXTENDED];

    trace!(">>> {}", hex::encode(&req));

    let rapdu = card.transmit(&req, &mut resp).map_err(|e| {
        error!("Failed to transmit APDU command to card: {}", e);
        e
    })?;

    trace!("<<< {}", hex::encode(rapdu));

    ISO7816ResponseAPDU::try_from(rapdu).map_err(|e| {
        error!("Failed to parse card response: {:?}", e);
        WebauthnCError::ApduTransmission
    })
}
/// Transmit multiple chunks of data to the card, and handle a chunked
/// response. All requests must be transmittable in short form.
pub fn transmit_chunks(
    card: &Card,
    requests: &[ISO7816RequestAPDU],
) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
    let mut r = EMPTY_RESPONSE;

    for chunk in requests {
        r = transmit(card, chunk, &ISO7816LengthForm::ShortOnly)?;
        if !r.is_success() {
            return Err(WebauthnCError::ApduTransmission);
        }
    }

    if r.ctap_needs_get_response() {
        error!("NFCCTAP_GETRESPONSE not supported, but token sent it");
        return Err(WebauthnCError::ApduTransmission);
    }

    if r.bytes_available() == 0 {
        return Ok(r);
    }

    let mut response_data = Vec::new();
    response_data.extend_from_slice(&r.data);

    while r.bytes_available() > 0 {
        r = transmit(
            card,
            &get_response(0x80, r.bytes_available()),
            &ISO7816LengthForm::ShortOnly,
        )?;
        if !r.is_success() {
            return Err(WebauthnCError::ApduTransmission);
        }
        response_data.extend_from_slice(&r.data);
    }

    r.data = response_data;
    Ok(r)
}

const DESELECT_APPLET: ISO7816RequestAPDU = ISO7816RequestAPDU {
    cla: 0x80,
    ins: 0x12,
    p1: 0x01,
    p2: 0x00,
    data: vec![],
    ne: 256,
};

impl NFCCard {
    pub fn new(ctx: &Context, reader_name: &CStr, atr: &[u8]) -> Result<NFCCard, WebauthnCError> {
        trace!("ATR: {}", hex::encode(atr));
        let atr = Atr::try_from(atr)?;
        trace!("Parsed: {:?}", &atr);
        trace!("issuer data: {:?}", atr.card_issuers_data_str());

        if atr.storage_card {
            return Err(WebauthnCError::StorageCard);
        }

        let card = ctx
            .connect(reader_name, ShareMode::Exclusive, Protocols::ANY)
            .map_err(|e| {
                error!("Error connecting to card: {:?}", e);
                e
            })?;

        Ok(NFCCard {
            card: Mutex::new(card),
            reader_name: reader_name.to_owned(),
            atr,
            initialised: false,
        })
    }

    #[cfg(feature = "nfc_raw_transmit")]
    /// Transmits a single ISO 7816-4 APDU to the card.
    ///
    /// This API is only intended for conformance testing.
    pub fn transmit(
        &self,
        request: &ISO7816RequestAPDU,
        form: &ISO7816LengthForm,
    ) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
        let guard = self.card.lock()?;
        transmit(guard.deref(), request, form)
    }

    /// Gets the name of the card reader being used to communicate with this
    /// token.
    pub fn reader_name(&self) -> Option<&str> {
        self.reader_name.to_str().ok()
    }
}

#[async_trait]
impl Token for NFCCard {
    type Id = CString;

    fn has_button(&self) -> bool {
        false
    }

    async fn transmit_raw<U>(&mut self, cmd: &[u8], _ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        if !self.initialised {
            error!("attempted to transmit to uninitialised card");
            return Err(WebauthnCError::Internal);
        }
        // let apdu = cmd.to_extended_apdu().map_err(|_| WebauthnCError::Cbor)?;
        // let mut resp = self.transmit(&apdu, &ISO7816LengthForm::ExtendedOnly)?;

        // while resp.ctap_needs_get_response() {
        //     // TODO: sleep here, add retry limit?
        //     info!("Needs GetResponse");

        //     resp = self.transmit(&NFCCTAP_GETRESPONSE, &ISO7816LengthForm::ExtendedOnly)?;
        // };
        let apdus = to_short_apdus(cmd);
        let guard = self.card.lock()?;
        let resp = transmit_chunks(guard.deref(), &apdus)?;
        let mut data = resp.data;
        let err = CtapError::from(data.remove(0));
        if !err.is_ok() {
            return Err(err.into());
        }

        Ok(data)
    }

    /// Initialises the connected FIDO token.
    ///
    /// ## Platform-specific issues
    ///
    /// ### Windows
    ///
    /// This may fail with "permission denied" on Windows 10 build 1903 or
    /// later, unless the program is run as Administrator.
    async fn init(&mut self) -> Result<(), WebauthnCError> {
        if self.initialised {
            warn!("attempted to init an already-initialised card");
            return Ok(());
        } else {
            // FIXME: macOS likes to drop in on our **exclusive** connection with a
            // SELECT(a0 00 00 03 08 00 00 10 00 01 00) (for the PIV applet). This
            // seems to confuse some cards.
            //
            // So, lets wait a moment for it to butt in.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let guard = self.card.lock()?;
        let resp = transmit(
            guard.deref(),
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ShortOnly,
        )?;

        if !resp.is_ok() {
            error!("Error selecting applet: {:02x} {:02x}", resp.sw1, resp.sw2);
            return Err(WebauthnCError::NotSupported);
        }

        if resp.data != APPLET_U2F_V2 && resp.data != APPLET_FIDO_2_0 {
            error!("Unsupported applet: {:02x?}", &resp.data);
            return Err(WebauthnCError::NotSupported);
        }

        self.initialised = true;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        if !self.initialised {
            // Card wasn't initialised, but close() may be called
            // unconditionally.
            return Ok(());
        }

        let guard = self.card.lock()?;
        let resp = transmit(
            guard.deref(),
            &DESELECT_APPLET,
            &ISO7816LengthForm::ShortOnly,
        )?;

        if !resp.is_ok() {
            Err(WebauthnCError::ApduTransmission)
        } else {
            Ok(())
        }
    }

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Nfc
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        // There does not appear to be a "cancel" command over NFC.
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ignored_readers() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt().try_init();

        // CCID interfaces on tokens
        const IGNORED: [&[u8]; 4] = [
            b"Nitrokey Nitrokey 3",
            b"Nitrokey Nitrokey 3 [CCID/ICCD Interface] 00 00",
            b"SoloKeys Solo 2",
            b"Yubico YubiKey FIDO+CCID",
        ];

        // Smartcard readers
        const ALLOWED: [&[u8]; 6] = [
            b"ACS ACR122U 00 00",
            b"ACS ACR122U 01 00",
            b"ACS ACR122U PICC Interface",
            b"ACS ACR123 3S Reader [ACR123U-PICC] (1.00.xx) 00 00",
            // Invalid UTF-8 should be allowed, even if it contains ignored
            // reader names.
            b"\xFF\xFF",
            b"\xFFYubico YubiKey FIDO+CCID\xFF",
        ];

        for n in IGNORED {
            let e = String::from_utf8(n.to_vec()).unwrap_or_else(|_| hex::encode(n));
            assert!(
                ignored_reader(&CString::new(n)?),
                "expected {e} to be ignored"
            );
        }

        for n in ALLOWED {
            let e = String::from_utf8(n.to_vec()).unwrap_or_else(|_| hex::encode(n));
            assert!(
                !ignored_reader(&CString::new(n)?),
                "expected {e} to be allowed"
            );
        }

        Ok(())
    }
}
