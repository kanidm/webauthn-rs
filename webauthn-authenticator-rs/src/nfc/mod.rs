//! [NFCReader] communicates with a FIDO token over NFC, using the [pcsc] API.
use crate::error::WebauthnCError;

use pcsc::*;
use std::ffi::CString;
use std::fmt;

mod atr;
mod tlv;

pub use self::atr::*;
use super::cbor::*;
use crate::transport::iso7816::*;
use crate::transport::*;

/// Version string for a token which supports CTAP v1 / U2F
pub const APPLET_U2F_V2: [u8; 6] = [0x55, 0x32, 0x46, 0x5f, 0x56, 0x32];
/// Version string for a token which only supports CTAP v2
pub const APPLET_FIDO_2_0: [u8; 8] = [0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30];
/// ISO 7816 FIDO applet name
pub const APPLET_DF: [u8; 8] = [
    /* RID */ 0xA0, 0x00, 0x00, 0x06, 0x47, /* PIX */ 0x2F, 0x00, 0x01,
];

pub struct NFCReader {
    ctx: Context,
    rdr_id: CString,
    rdr_state: Vec<ReaderState>,
}

pub struct NFCCard {
    // rdr: &'a NFCReader,
    card_ref: Card,
    pub atr: Atr,
}

impl fmt::Debug for NFCReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCReader")
            .field("reader_id", &self.rdr_id)
            .finish()
    }
}

impl fmt::Debug for NFCCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCCard").field("atr", &self.atr).finish()
    }
}

impl Default for NFCReader {
    fn default() -> Self {
        let ctx = Context::establish(Scope::User).expect("Failed to establish pcsc context");

        let mut readers_buf = [0; 2048];
        let mut readers = ctx
            .list_readers(&mut readers_buf)
            .expect("Failed to list pcsc readers");

        let rdr_id = readers
            .next()
            .map(|s| s.to_owned())
            .expect("No pcsc readers are connected.");

        let mut rdr_state = vec![ReaderState::new(rdr_id.clone(), State::UNAWARE)];

        for read_state in &mut rdr_state {
            read_state.sync_current_state();
        }

        info!("Using reader: {:?}", rdr_id);
        NFCReader {
            ctx,
            rdr_id,
            rdr_state,
        }
    }
}

impl NFCReader {
    pub fn wait_for_card(&mut self) -> Result<NFCCard, ()> {
        loop {
            for read_state in &mut self.rdr_state {
                read_state.sync_current_state();
            }

            if let Err(e) = self.ctx.get_status_change(None, &mut self.rdr_state) {
                error!("Failed to detect card: {:?}", e);
                return Err(());
            } else {
                // Check every reader ...
                for read_state in &self.rdr_state {
                    trace!("rdr_state: {:?}", read_state.event_state());
                    let state = read_state.event_state();
                    if state.contains(State::PRESENT) {
                        // Setup the card, and return it.
                        let card_ref = self
                            .ctx
                            .connect(&self.rdr_id, ShareMode::Shared, Protocols::ANY)
                            .expect("Failed to access NFC card");
                        return Ok(NFCCard::new(card_ref));
                    } else if state.contains(State::EMPTY) {
                        info!("Card removed");
                    } else {
                        warn!("Unknown state change -> {:?}", state);
                    }
                }
            }
        } // end loop.
    }
}

impl Transport for NFCReader {
    type Token = NFCCard;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        for read_state in &mut self.rdr_state {
            read_state.sync_current_state();
        }

        if let Err(e) = self.ctx.get_status_change(None, &mut self.rdr_state) {
            error!("Failed to detect card: {:?}", e);
            return Err(WebauthnCError::Internal);
        }

        // Check every reader ...
        let r: Result<Vec<NFCCard>, WebauthnCError> = self
            .rdr_state
            .iter()
            .filter(|s| s.event_state().contains(State::PRESENT))
            .map(|s| {
                self.ctx
                    .connect(&s.name(), ShareMode::Shared, Protocols::ANY)
                    .map(NFCCard::new)
                    .map_err(|_| WebauthnCError::Internal)
            })
            .collect();

        r
    }
}

fn transmit(
    card: &Card,
    request: &ISO7816RequestAPDU,
    form: ISO7816LengthForm,
) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
    let req = request.to_bytes(form).map_err(|e| {
        error!("Failed to build APDU command: {:?}", e);
        WebauthnCError::ApduConstruction
    })?;
    let mut resp = vec![0; MAX_BUFFER_SIZE_EXTENDED];

    trace!(">>> {:02x?}", req);

    let rapdu = card.transmit(&req, &mut resp).map_err(|e| {
        error!("Failed to transmit APDU command to card: {}", e);
        WebauthnCError::ApduTransmission
    })?;

    trace!("<<< {:02x?}", rapdu);

    ISO7816ResponseAPDU::try_from(rapdu).map_err(|e| {
        error!("Failed to parse card response: {:?}", e);
        WebauthnCError::ApduTransmission
    })
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
    pub fn new(card_ref: Card) -> NFCCard {
        let mut names_buf = vec![0; MAX_BUFFER_SIZE];
        let mut atr_buf = vec![0; MAX_ATR_SIZE];

        let card_status = card_ref
            .status2(&mut names_buf, &mut atr_buf)
            .expect("error getting status");

        trace!("ATR: {:02x?}", card_status.atr());
        let atr = Atr::try_from(card_status.atr()).expect("oops atr");
        trace!("Parsed: {:?}", &atr);

        let card = NFCCard { card_ref, atr: atr };
        return card;
    }

    /// Transmits a single ISO 7816-4 APDU to the card.
    pub fn transmit(
        &self,
        request: &ISO7816RequestAPDU,
        form: ISO7816LengthForm,
    ) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
        transmit(&self.card_ref, request, form)
    }

    /// Transmit multiple chunks of data to the card, and handle a chunked
    /// response. All requests must be transmittable in short form.
    pub fn transmit_chunks(
        &self,
        requests: &[ISO7816RequestAPDU],
    ) -> Result<ISO7816ResponseAPDU, WebauthnCError> {
        let mut r = EMPTY_RESPONSE;

        for chunk in requests {
            r = self.transmit(chunk, ISO7816LengthForm::ShortOnly)?;
            if !r.is_success() {
                return Err(WebauthnCError::ApduTransmission);
            }
        }

        if r.ctap_needs_get_response() {
            unimplemented!("NFCCTAP_GETRESPONSE");
        }

        if r.bytes_available() == 0 {
            return Ok(r);
        }

        let mut response_data = Vec::new();
        response_data.extend_from_slice(&r.data);

        while r.bytes_available() > 0 {
            r = self.transmit(
                &get_response(0x80, r.bytes_available()),
                ISO7816LengthForm::ShortOnly,
            )?;
            if !r.is_success() {
                return Err(WebauthnCError::ApduTransmission);
            }
            response_data.extend_from_slice(&r.data);
        }

        r.data = response_data;
        Ok(r)
    }
}

impl Token for NFCCard {
    fn transmit<'a, C, R>(&self, cmd: C) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        let apdus = cmd.to_short_apdus().unwrap();
        let resp = self.transmit_chunks(&apdus)?;

        // CTAP has its own extra status code over NFC in the first byte.
        // TODO: handle status byte
        R::try_from(&resp.data[1..]).map_err(|_| {
            //error!("error: {:?}", e);
            WebauthnCError::Cbor
        })
    }

    fn init(&mut self) -> Result<(), WebauthnCError> {
        let resp = self
            .transmit(&select_by_df_name(&APPLET_DF), ISO7816LengthForm::ShortOnly)
            .expect("Failed to select CTAP2.1 applet");

        if !resp.is_ok() {
            error!("Error selecting applet: {:02x} {:02x}", resp.sw1, resp.sw2);
            return Err(WebauthnCError::NotSupported);
        }

        if resp.data != &APPLET_U2F_V2 {
            error!("Unsupported applet: {:02x?}", &resp.data);
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        let resp = self
            .transmit(&DESELECT_APPLET, ISO7816LengthForm::ShortOnly)
            .expect("Failed to deselect CTAP2.1 applet");

        if !resp.is_ok() {
            Err(WebauthnCError::ApduTransmission)
        } else {
            Ok(())
        }
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
