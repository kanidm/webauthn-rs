//! [NFCReader] communicates with a FIDO token over NFC, using the [pcsc] API.
use crate::ctap2::commands::to_short_apdus;
use crate::error::{CtapError, WebauthnCError};
use crate::ui::UiCallback;

use async_trait::async_trait;
use futures::executor::block_on;
use pcsc::*;
use std::ffi::{CStr, CString};
use std::fmt;
use std::ops::Deref;
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

/// Wrapper for PC/SC context
pub struct NFCReader {
    ctx: Context,
    reader_states: Vec<(CString, State, Vec<u8>)>,
}

// Connection to a single NFC card
pub struct NFCCard {
    card: Mutex<Card>,
    reader_name: CString,
    pub atr: Atr,
}

impl fmt::Debug for NFCReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCReader").finish()
    }
}

impl fmt::Debug for NFCCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCCard")
            .field("reader_name", &self.reader_name)
            .field("atr", &self.atr)
            .finish()
    }
}

impl NFCReader {
    /// Creates a new [NFCReader] instance in a given [Scope].
    ///
    /// Example:
    ///
    /// ```rust
    /// use pcsc::Scope;
    /// use webauthn_authenticator_rs::nfc::NFCReader;
    ///
    /// let reader = NFCReader::new(Scope::User);
    /// // TODO: Handle errors
    /// ```
    pub fn new(scope: Scope) -> Result<Self, WebauthnCError> {
        Ok(NFCReader {
            ctx: Context::establish(scope).map_err(WebauthnCError::PcscError)?,
            reader_states: vec![],
        })
    }

    /// Copies [Self::reader_states] into a native structure.
    fn get_native_reader_states(&self) -> Vec<ReaderState> {
        self.reader_states
            .iter()
            .map(|(name, state, _)| ReaderState::new(name.clone(), *state))
            .collect()
    }

    /// Replaces [Self::reader_states] with native values.
    fn set_native_reader_states(&mut self, reader_states: Vec<ReaderState>) {
        self.reader_states.clear();
        for reader_state in reader_states {
            self.reader_states.push((
                reader_state.name().to_owned(),
                reader_state.event_state(),
                reader_state.atr().to_vec(),
            ));
        }
    }

    /// Updates the state of all readers.
    fn update_reader_states(&mut self) -> Result<(), WebauthnCError> {
        trace!(
            "{} known reader(s), pruning ignored readers",
            self.reader_states.len()
        );
        // Remove all disconnected readers
        let mut i = 0;
        while i < self.reader_states.len() {
            if self.reader_states[i].1.contains(State::IGNORE) {
                self.reader_states.remove(i);
            } else {
                i += 1;
            }
        }
        trace!(
            "{} reader(s) remain after pruning",
            self.reader_states.len()
        );

        // Get a list of readers right now
        let readers = self.ctx.list_readers_owned()?;
        trace!(
            "{} reader(s) currently connected: {:?}",
            readers.len(),
            readers
        );

        // Add any new readers to the list
        for reader_name in readers {
            if !self.reader_states.iter().any(|s| s.0 == reader_name) {
                // New reader
                trace!("New reader: {:?}", reader_name);
                self.reader_states
                    .push((reader_name, State::UNAWARE, vec![]));
            }
        }

        // Update all reader states
        let mut native_states = self.get_native_reader_states();
        if native_states.is_empty() {
            trace!("No readers to update, not probing states");
            return Ok(());
        }
        trace!("Updating all {} reader states", native_states.len());
        let r = self
            .ctx
            .get_status_change(Duration::from_millis(500), &mut native_states);

        if let Err(e) = r {
            if e != pcsc::Error::Timeout {
                r?;
            }
        }

        trace!("Updated reader states");
        self.set_native_reader_states(native_states);

        Ok(())
    }

    pub fn wait_for_card(&mut self) -> Result<NFCCard, WebauthnCError> {
        loop {
            self.update_reader_states()?;
            // Check every reader ...
            for read_state in &self.reader_states {
                trace!("rdr_state: {:?}", read_state);
                let (name, state, atr) = read_state;
                if state.contains(State::PRESENT) {
                    let card = NFCCard::new(self, name, atr);
                    match card {
                        Ok(c) => return Ok(c),
                        Err(e) => error!("Error accessing card: {:?}", e),
                    }
                }
            }
        } // end loop.
    }
}

#[async_trait]
impl<'b> Transport<'b> for NFCReader {
    type Token = NFCCard;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        // FIXME: this API doesn't work too well for NFC - you could have a
        // reader which has no card in the field; and at which point you can
        // do a SELECT and GetInfoRequest to see if it's for us.
        //
        // Maybe have the concept of an "empty port" to handle this better.

        self.update_reader_states()?;

        // Check every reader ...
        trace!("Checking all readers");
        let r: Vec<NFCCard> = self
            .reader_states
            .iter()
            .filter(|(_, state, _)| state.contains(State::PRESENT))
            .filter_map(|(name, _, atr)| NFCCard::new(self, name, atr).ok())
            .filter_map(|mut c| {
                block_on(c.init()).ok()?;
                Some(c)
            })
            .collect();

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

    trace!(">>> {:02x?}", req);

    let rapdu = card.transmit(&req, &mut resp).map_err(|e| {
        error!("Failed to transmit APDU command to card: {}", e);
        e
    })?;

    trace!("<<< {:02x?}", rapdu);

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
    pub fn new(
        reader: &NFCReader,
        reader_name: &CStr,
        atr: &[u8],
    ) -> Result<NFCCard, WebauthnCError> {
        trace!("ATR: {:02x?}", atr);
        let atr = Atr::try_from(atr)?;
        trace!("Parsed: {:?}", &atr);

        if atr.storage_card {
            return Err(WebauthnCError::StorageCard);
        }

        let card = reader
            .ctx
            .connect(reader_name, ShareMode::Exclusive, Protocols::ANY)
            .map_err(|e| {
                error!("Error connecting to card: {:?}", e);
                e
            })?;

        Ok(NFCCard {
            card: Mutex::new(card),
            reader_name: reader_name.to_owned(),
            atr,
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
}

#[async_trait]
impl Token for NFCCard {
    fn has_button(&self) -> bool {
        false
    }

    async fn transmit_raw<U>(&mut self, cmd: &[u8], _ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
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

        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
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

    fn cancel(&self) -> Result<(), WebauthnCError> {
        // There does not appear to be a "cancel" command over NFC.
        Ok(())
    }
}

/*
impl<'a> NFCCtap2<'a> {
    fn default(rdr: &'a NFCReader) -> Self {
        let card_ref = rdr.ctx
            .connect(&rdr.rdr_id, ShareMode::Shared, Protocols::ANY)
            .expect("Failed to access NFC card");

        // We need to SETUUUUUPPPPPP to talk to ctap2
        debug!("Sending APDU: {:x?}", &APPLET_SELECT_CMD);
        let mut rapdu_buf = [0; MAX_SHORT_BUFFER_SIZE];
        let rapdu = card_ref
            .transmit(&APPLET_SELECT_CMD, &mut rapdu_buf)
            .expect("Failed to select CTAP2.1 applet");

        if rapdu == &APPLET_U2F_V2 {
            info!("Selected U2F_V2 applet");
        } else {
            panic!("Invalid response from CTAP2.1 request");
        };

        NFCCtap2 {
            card: NFCCard {
                card_ref, rdr
            }
        }
    }

    pub fn authenticator_get_info(
        &mut self,
    ) -> Result<AuthenticatorGetInfoResponse, WebauthnCError> {
        let rapdu = self.card.transmit_pdu(&AUTHENTICATOR_GET_INFO_APDU)?;
        AuthenticatorGetInfoResponse::try_from(rapdu.as_slice()).map_err(|e| {
            error!(?e);
            WebauthnCError::Cbor
        })
    }
}
*/

/*
impl U2FToken for NFC {
    fn perform_u2f_register(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        //
        platform_attached: bool,
        resident_key: bool,
        user_verification: bool,
    ) -> Result<U2FRegistrationData, WebauthnCError> {
        unimplemented!();
    }

    fn perform_u2f_sign(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        // list of creds
        allowed_credentials: &[AllowCredentials],
        user_verification: bool,
    ) -> Result<U2FSignData, WebauthnCError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use crate::nfc::NFC;
    use crate::WebauthnAuthenticator;
    use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
    use webauthn_rs::Webauthn;

    #[test]
    fn webauthn_authenticator_wan_nfc_interact() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        let wan_c = WebauthnEphemeralConfig::new(
            "https://localhost:8080/auth",
            "https://localhost:8080",
            "localhost",
            None,
        );

        let wan = Webauthn::new(wan_c);

        let username = "william".to_string();

        let (chal, reg_state) = wan.generate_challenge_register(&username, false).unwrap();

        println!("🍿 challenge -> {:x?}", chal);

        // We can vie the nfc info.
        let mut nfc = NFC::default();
        println!("{:?}", nfc.authenticator_get_info());

        let mut wa = WebauthnAuthenticator::new(nfc);
        let r = wa
            .do_registration("https://localhost:8080", chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to register");

        let (cred, _reg_data) = wan
            .register_credential(&r, &reg_state, |_| Ok(false))
            .unwrap();

        let (chal, auth_state) = wan.generate_challenge_authenticate(vec![cred]).unwrap();

        let r = wa
            .do_authentication("https://localhost:8080", chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to auth");

        let auth_res = wan
            .authenticate_credential(&r, &auth_state)
            .expect("webauth authentication denied");
        info!("auth_res -> {:x?}", auth_res);
    }
}
*/
