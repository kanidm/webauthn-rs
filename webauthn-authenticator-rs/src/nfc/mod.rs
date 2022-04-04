use crate::error::WebauthnCError;
use crate::U2FToken;
use crate::{U2FRegistrationData, U2FSignData};
use base64urlsafedata::Base64UrlSafeData;

use webauthn_rs_proto::{
    AllowCredentials, PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User,
};

use pcsc::*;
use std::ffi::{CStr, CString};
use std::fmt;

pub mod apdu;

use self::apdu::*;

pub struct NFCReader {
    ctx: Context,
    rdr_id: CString,
    rdr_state: Vec<ReaderState>,
}

pub struct NFCCard<'a> {
    rdr: &'a NFCReader,
    card_ref: Card,
}

pub enum Selected<'a> {
    // FIDO_2_1(),
    FIDO_2_1_PRE(Ctap2_1_pre<'a>),
    // FIDO_2_0(),
    // U2F(),
}

pub struct Ctap2_1_pre<'a> {
    tokinfo: AuthenticatorGetInfoResponse,
    card: NFCCard<'a>,
}

impl fmt::Debug for NFCReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NFCReader")
            .field("reader_id", &self.rdr_id)
            .finish()
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
    pub fn wait_for_card(&mut self) -> Result<NFCCard<'_>, ()> {
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
                        return Ok(NFCCard {
                            card_ref,
                            rdr: self,
                        });
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

#[derive(Debug)]
enum Pdu<'b> {
    Fragment(&'b [u8]),
    Complete(&'b [u8]),
}

impl<'a> NFCCard<'a> {
    fn transmit_raw(
        &mut self,
        tx_buf: &[u8],
        rx_buf: &mut Vec<u8>,
    ) -> Result<[u8; 2], WebauthnCError> {
        trace!("Sending raw APDU: {:x?}", tx_buf);
        let mut rapdu_buf = vec![0; MAX_SHORT_BUFFER_SIZE];
        // The returned slice gives us the correct lengths of what
        // was filled to buf.
        let rapdu = self
            .card_ref
            .transmit(&tx_buf, &mut rapdu_buf)
            .map_err(|e| {
                error!("Failed to transmit APDU command to card: {}", e);
                WebauthnCError::ApduTransmission
            })?;
        let (data, status) = rapdu.split_at(rapdu.len() - 2);
        rx_buf.extend_from_slice(data);
        Ok(status.try_into().expect("Status not 2 bytes??!?!?!"))
    }

    // This handles frag/defrag
    fn transmit_pdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let mut ans = Vec::with_capacity(MAX_SHORT_BUFFER_SIZE);
        let mut tx_buf = Vec::with_capacity(MAX_SHORT_BUFFER_SIZE);

        // Fragmentation works by sending chunks with a frag_cmd, until you complete the chunks
        // with a cmd that has the correct apply header.
        //
        // We reverse the list, so that if there is only a single chunk we apply the correct header
        // in a generic way.
        let mut pdu_chunk_iter = apdu.chunks(FRAG_MAX as usize).rev();

        // For the "last" chunk, we need to signal that we are done, so we send this with the
        // applet header.
        let mut chunks = Vec::new();
        match pdu_chunk_iter.next() {
            Some(chunk_last) => chunks.push(Pdu::Complete(chunk_last)),
            None => return Err(WebauthnCError::ApduTransmission),
        };
        // Now push the fragments
        for chunk_next in pdu_chunk_iter {
            chunks.push(Pdu::Fragment(chunk_next));
        }

        trace!("{:x?}", chunks);

        let mut need_more = false;
        for pdu in chunks.into_iter().rev() {
            tx_buf.clear();
            match pdu {
                Pdu::Fragment(data) => {
                    tx_buf.extend_from_slice(&FRAG_HDR);
                    tx_buf.push(data.len() as u8);
                    tx_buf.extend_from_slice(data);
                }
                Pdu::Complete(data) => {
                    tx_buf.extend_from_slice(&HDR);
                    tx_buf.push(data.len() as u8);
                    tx_buf.extend_from_slice(data);
                    tx_buf.push(0x00);
                }
            }
            let status = self.transmit_raw(&tx_buf, &mut ans)?;

            trace!("{:x?}", status);
            match pdu {
                Pdu::Fragment(data) => {
                    trace!("{:x?}", ans);
                    debug_assert!(ans.len() == 0);
                    if status != [0x90, 0x00] {
                        return Err(WebauthnCError::ApduTransmission);
                    }
                }
                Pdu::Complete(data) => {
                    trace!("{:x?}", ans);
                    if status == [0x90, 0x00] {
                        // All good :)
                        continue;
                    } else if status == [0x61, 0x00] {
                        need_more = true;
                    } else {
                        return Err(WebauthnCError::ApduTransmission);
                    }
                }
            }
            trace!(?need_more);
        }

        if need_more {
            // We need to req more ...
        }

        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
        let ctap_status = ans.remove(0);
        debug!("{:x?}", ctap_status);

        Ok(ans)
    }

    fn authenticator_get_info(&mut self) -> Result<AuthenticatorGetInfoResponse, WebauthnCError> {
        let rapdu = self.transmit_pdu(&AUTHENTICATOR_GET_INFO_APDU)?;
        AuthenticatorGetInfoResponse::try_from(rapdu.as_slice()).map_err(|e| {
            error!(?e);
            WebauthnCError::Cbor
        })
    }

    // Need a way to select the type of card now.
    pub fn select_u2f_v2_applet(mut self) -> Result<Selected<'a>, WebauthnCError> {
        let mut rapdu_buf = [0; MAX_SHORT_BUFFER_SIZE];
        let rapdu = self
            .card_ref
            .transmit(&APPLET_SELECT_CMD, &mut rapdu_buf)
            .expect("Failed to select CTAP2.1 applet");
        if rapdu == &APPLET_U2F_V2 {
            trace!("Selected U2F_V2 applet successfully");
        } else {
            return Err(WebauthnCError::NotSupported);
        };

        // Read the card info.
        let tokinfo = self.authenticator_get_info()?;

        debug!(?tokinfo);

        if tokinfo.versions.contains("FIDO_2_1_PRE") {
            Ok(Selected::FIDO_2_1_PRE(Ctap2_1_pre {
                tokinfo,
                card: self,
            }))
        } else {
            error!(?tokinfo.versions);
            return Err(WebauthnCError::NotSupported);
        }
    }
}

impl<'a> fmt::Debug for Ctap2_1_pre<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctap2_1_pre<'_>")
            .field("token_info", &self.tokinfo)
            .finish()
    }
}

impl<'a> Ctap2_1_pre<'a> {
    pub fn hack_make_cred(&mut self) -> Result<(), WebauthnCError> {
        let mc = AuthenticatorMakeCredential {
            client_data_hash: vec![
                104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226,
                47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65,
            ],
            rp: RelyingParty {
                name: "test".to_string(),
                id: "test".to_string(),
            },
            user: User {
                id: Base64UrlSafeData("test".as_bytes().into()),
                name: "test".to_string(),
                display_name: "test".to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };
        let pdu = mc.to_apdu();
        let rapdu = self.card.transmit_pdu(&pdu)?;
        trace!("got encoded APDU: {:x?}", rapdu);

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
