//! [NFCReader] communicates with a FIDO token over NFC, using the [pcsc] API.
use crate::error::{CtapError, WebauthnCError};
use crate::transport::ctap21pre::Ctap21PreAuthenticator;
use crate::ui::UiCallback;

use async_trait::async_trait;
use futures::executor::block_on;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use pcsc::*;
use std::ffi::CString;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use webauthn_rs_proto::AuthenticatorTransport;

mod atr;
mod tlv;
mod worker;

pub use self::atr::*;
use self::worker::{PcscWorker, WorkerCmd, WorkerMsg};
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
    receiver: Mutex<Receiver<WorkerMsg>>,
    sender: Sender<WorkerCmd>,
    worker: JoinHandle<()>,

    // todo: add lock?
}

pub struct NFCCard {
    reader: fn(&[u8]) -> Vec<u8>,
    reader_name: String,
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

impl Default for NFCReader {
    fn default() -> Self {
        let (receiver, sender, worker) = PcscWorker::new();

        NFCReader {
            receiver: Mutex::new(receiver),
            sender,
            worker,
        }
    }
}


impl NFCReader {

    /*
    /// Gets the state of all monitored readers.
    fn get_reader_states(&self) -> Vec<ReaderState> {
        self.reader_names
            .iter()
            .map(|n| {
                let mut s = ReaderState::new(n.clone(), State::UNAWARE);
                s.sync_current_state();
                s
            })
            .collect()
    }

    pub fn wait_for_card(&mut self) -> Result<NFCCard, WebauthnCError> {
        loop {
            for read_state in &mut self.rdr_state {
                read_state.sync_current_state();
            }

            if let Err(e) = self.ctx.get_status_change(None, &mut self.rdr_state) {
                error!("Failed to detect card: {:?}", e);
                return Err(WebauthnCError::Internal);
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
    */
}

#[async_trait]
impl<'b> Transport<'b> for NFCReader {
    type Token = NFCCard;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        let guard = self.receiver.lock().unwrap();
        self.sender.send(WorkerCmd::ListReaders).unwrap();

        let reader_states = loop {
            let r = guard.recv().unwrap();
            if let WorkerMsg::ReaderList(l) = r {
                break l;
            }
        };
        // let mut reader_states = MutexedReaderStates::new(self.get_reader_states());
        // reader_states.get_status_change(&self.ctx)?;

        // Check every reader ...
        let r: Vec<NFCCard> = reader_states
            .drain(..)
            .filter(|(_, state, _)| state.contains(State::PRESENT))
            .filter_map(|(name, _, atr)| NFCCard::new(&self, name, atr).ok())
            .filter_map(|mut c| {
                block_on(c.init()).ok()?;
                Some(c)
            })
            .collect();

        Ok(r)
    }

    async fn select_one_token<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<ctap21pre::Ctap21PreAuthenticator<'a, Self::Token, U>, WebauthnCError> {
        todo!()
        // let mut reader_states: MutexedReaderStates =
        //     MutexedReaderStates::new(self.get_reader_states());
        // loop {
        //     reader_states.get_status_change(&self.ctx)?;

        //     // Check every reader ...
        //     let all_tokens: Vec<NFCCard> = reader_states
        //         .iter()
        //         .filter(|s| s.event_state().contains(State::PRESENT))
        //         .filter_map(|s| NFCCard::new(&self.ctx, s).ok())
        //         .filter_map(|mut c| {
        //             block_on(c.init()).ok()?;
        //             Some(c)
        //         })
        //         .collect();

        //     let mut tasks: FuturesUnordered<_> = all_tokens
        //         .drain(..)
        //         .map(|mut token| {
        //             async move {
        //                 let info = match token.transmit(GetInfoRequest {}, ui).await {
        //                     Ok(info) => {
        //                         if !(info.versions.contains("FIDO_2_1_PRE")
        //                             || info.versions.contains("FIDO_2_0")
        //                             || info.versions.contains("FIDO_2_1"))
        //                         {
        //                             trace!("dropping unsupported token");
        //                             return None;
        //                         }
        //                         info
        //                     }
        //                     Err(_) => return None,
        //                 };

        //                 // No need to selectionRequest
        //                 Some((info, Mutex::new(token)))
        //             }
        //             .fuse()
        //         })
        //         .collect();

        //     loop {
        //         select! {
        //             res = tasks.select_next_some() => {
        //                 if let Some((info, mutex)) = res {
        //                     trace!(?info);
        //                     match mutex.into_inner() {
        //                         Ok(guard) => return Ok(Ctap21PreAuthenticator::new(info, guard, ui)),
        //                         _ => (),
        //                     }
        //                 }
        //             }
        //             complete => {
        //                 // No tokens available
        //                 return Err(WebauthnCError::NoSelectedToken);
        //             }
        //         }
        //     }
        // } // end loop.

        // // Nothing picked
        // Err(WebauthnCError::NoSelectedToken)
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
        WebauthnCError::ApduTransmission
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

impl<'a> NFCCard {
    pub fn new(reader: &NFCReader, reader_name: String, atr: Vec<u8>) -> Result<NFCCard, WebauthnCError> {
        trace!("ATR: {:02x?}", atr);
        let atr = Atr::try_from(atr.as_slice()).expect("oops atr");
        trace!("Parsed: {:?}", &atr);
        // TODO: check that it's not a storage card

        reader.sender.send(WorkerCmd::Connect(reader_name));

        // TODO: error handler
        let s= reader.sender.clone();
        let transmit = move |apdu | {
            let guard = reader.receiver.lock().unwrap();
            s.send(WorkerCmd::Transmit(reader_name, apdu));
            loop {
                let r = guard.recv().unwrap();
                if let WorkerMsg::Receive(_, apdu) = r {
                    return apdu;
                }
            }
        };

        Ok(NFCCard {
            reader: transmit,
            reader_name,
            atr,
        })
    }
}

#[async_trait]
impl Token for NFCCard {
    async fn transmit_raw<C, U>(&self, cmd: C, _ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        C: CBORCommand,
        U: UiCallback,
    {
        // let apdu = cmd.to_extended_apdu().map_err(|_| WebauthnCError::Cbor)?;
        // let mut resp = self.transmit(&apdu, &ISO7816LengthForm::ExtendedOnly)?;

        // while resp.ctap_needs_get_response() {
        //     // TODO: sleep here, add retry limit?
        //     info!("Needs GetResponse");

        //     resp = self.transmit(&NFCCTAP_GETRESPONSE, &ISO7816LengthForm::ExtendedOnly)?;
        // };
        let guard = self.card_ref.lock().unwrap();
        let apdus = cmd.to_short_apdus().map_err(|_| WebauthnCError::Cbor)?;
        let resp = transmit_chunks(guard.deref(), &apdus)?;
        let mut data = resp.data;
        let err = CtapError::from(data.remove(0));
        if !err.is_ok() {
            return Err(err.into());
        }

        Ok(data)
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        let guard = self.card_ref.lock().unwrap();
        let resp = transmit(
            guard.deref(),
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ExtendedOnly,
        )
        .expect("Failed to select CTAP2.1 applet");

        if !resp.is_ok() {
            error!("Error selecting applet: {:02x} {:02x}", resp.sw1, resp.sw2);
            return Err(WebauthnCError::NotSupported);
        }

        if resp.data != APPLET_U2F_V2 {
            error!("Unsupported applet: {:02x?}", &resp.data);
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        let guard = self.card_ref.lock().unwrap();
        let resp = transmit(
            guard.deref(),
            &DESELECT_APPLET,
            &ISO7816LengthForm::ShortOnly,
        )
        .expect("Failed to deselect CTAP2.1 applet");

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
