use pcsc::*;
use std::ffi::CStr;

use webauthn_authenticator_rs::nfc::apdu::*;

fn access_card(ctx: &Context, reader: &CStr) {
    info!("Card detected ...");
    // Connect to the card.
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            info!("A smartcard is not present in the reader.");
            return;
        }
        Err(err) => {
            error!("Failed to connect to card: {}", err);
            return;
        }
    };

    // Select ctap2.1 via an APDU command.
    debug!("Sending APDU: {:x?}", &APPLET_SELECT_CMD);
    let mut rapdu_buf = [0; MAX_SHORT_BUFFER_SIZE];
    let rapdu = match card.transmit(&APPLET_SELECT_CMD, &mut rapdu_buf) {
        Ok(rapdu) => rapdu,
        Err(err) => {
            error!("Failed to transmit APDU command to card: {}", err);
            return;
        }
    };

    if rapdu == &APPLET_U2F_V2 {
        info!("Selected U2F_V2 applet");

        let mut rapdu_buf = [0; MAX_SHORT_BUFFER_SIZE];
        debug!("Sending APDU: {:x?}", &AUTHENTICATOR_GET_INFO_APDU);
        let rapdu = match card.transmit(&AUTHENTICATOR_GET_INFO_APDU, &mut rapdu_buf) {
            Ok(rapdu) => rapdu,
            Err(err) => {
                error!("Failed to transmit APDU command to card: {}", err);
                return;
            }
        };
        trace!("got raw APDU response: {:?}", rapdu);

        let agir = AuthenticatorGetInfoResponse::try_from(rapdu).unwrap();
        trace!("got response: {:?}", agir);
        info!("versions: {:?}", agir.versions);
        info!("extensions: {:?}", agir.extensions);
        info!("aaguid: {:?}", agir.aaguid);
        info!("options: {:?}", agir.options);
        info!("max_msg_size: {:?}", agir.max_msg_size);
        info!("pin_protocols: {:?}", agir.pin_protocols);
        info!("max_cred_count_in_list: {:?}", agir.max_cred_count_in_list);
        info!("max_cred_id_len: {:?}", agir.max_cred_id_len);
        info!("transports: {:?}", agir.transports);
        info!("algorithms: {:?}", agir.algorithms)
    } else {
        error!("UNKNOWN APDU response: {:x?}", rapdu);
    }
}

pub(crate) fn event_loop() {
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/index.html
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            error!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            info!("No readers are connected.");
            return;
        }
    };
    info!("Using reader: {:?}", reader);

    let mut reader_states = vec![
        // I think this is for when a new reader is connected.
        // ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
        ReaderState::new(reader, State::UNAWARE),
    ];

    loop {
        for read_state in &mut reader_states {
            read_state.sync_current_state();
        }

        if let Err(e) = ctx.get_status_change(None, &mut reader_states) {
            error!("Failed to detect card: {:?}", e);
            std::process::exit(1);
        } else {
            // Check every reader ...
            for read_state in &reader_states {
                trace!("reader_state: {:?}", read_state.event_state());
                let state = read_state.event_state();
                if state.contains(State::PRESENT) {
                    access_card(&ctx, reader);
                } else if state.contains(State::EMPTY) {
                    info!("Card removed");
                } else {
                    warn!("Unknown state change -> {:?}", state);
                }
            }
        }
    }
}
