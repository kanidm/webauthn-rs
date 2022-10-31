use futures::executor::block_on;
use webauthn_authenticator_rs::ctap2::{*, commands::*};
use webauthn_authenticator_rs::nfc::*;
use webauthn_authenticator_rs::transport::iso7816::*;

#[allow(dead_code)]
#[derive(Debug)]
enum TestResult {
    Skipped(&'static str),
    Pass,
    Fail(&'static str),
}

type Test = fn(&NFCCard) -> TestResult;

/// For cards which declare support for extended Lc/Le, check that they actually
/// support it for the SELECT command.
fn test_extended_lc_select(card: &NFCCard) -> TestResult {
    if card.atr.extended_lc != Some(true) {
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#nfc-framing
        return TestResult::Fail("FIDO 2.x authenticators MUST support extended Lc/Le, but this authenticator does not declare support for extended APDUs in the historical bytes");
    }

    // Test with Le = 256 in extended mode
    let resp = card
        .transmit(
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ExtendedOnly,
        )
        .expect("Failed to select applet");

    // Check error codes
    if resp.is_ok() {
        TestResult::Pass
    } else {
        TestResult::Fail("Card reports supporting extended Lc/Le in the historical bytes, but doesn't support it for SELECT")
    }
}

/// For cards which declare support for extended Lc/Le, check that they actually
/// support it for the `NFCCTAP_MSG` command.
fn test_extended_lc_info(card: &NFCCard) -> TestResult {
    if card.atr.extended_lc != Some(true) {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#nfc-framing
        return TestResult::Fail("FIDO 2.1 authenticators MUST support extended Lc/Le, but this authenticator does not declare support for extended APDUs in the historical bytes");
    }

    // Select the applet, but only use short form
    let mut resp = card
        .transmit(
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ShortOnly,
        )
        .expect("Failed to select applet");

    if !resp.is_ok() {
        return TestResult::Fail("Could not select CTAP applet");
    }

    // Check return value
    if resp.data != APPLET_U2F_V2 {
        return TestResult::Fail("Unsupported CTAP applet");
    }

    let mut get_info = (GetInfoRequest {}).to_extended_apdu().unwrap();
    get_info.ne = 65536;
    resp = card
        .transmit(&get_info, &ISO7816LengthForm::Extended)
        .expect("Failed to get info, ne=65536");

    if !resp.is_ok() {
        return TestResult::Fail(
            "Authenticator did not return 'OK' response for GetInfo and ne=65536",
        );
    }

    if resp.data.is_empty() || resp.data[0] != 0 {
        return TestResult::Fail("Authenticator did not return 'SUCCESS' CTAP error code.");
    }

    // We should be able to parse it, too...
    let info = <GetInfoResponse as CBORResponse>::try_from(&resp.data[1..]);

    if info.is_err() {
        return TestResult::Fail("Error parsing CBOR response");
    }

    trace!("{:?}", info.unwrap());

    get_info.ne = resp.data.len();
    if get_info.ne >= 256 {
        // We don't want to run this part of the test unless Ne < 256, so give
        // an early pass.
        return TestResult::Pass;
    }

    // Repeat the request, but with an Ne that should allow short form... but
    // use long form anyway. Nothing about ISO 7816-4 requires you to use short
    // form when a card says it supports it!
    let resp2 = card
        .transmit(&get_info, &ISO7816LengthForm::Extended)
        .expect("Failed to get info, ne=255");

    if resp2.is_ok() {
        if resp.data == resp2.data {
            TestResult::Pass
        } else {
            TestResult::Fail("Authenticator gave different responses for ne<256 and ne=65536")
        }
    } else {
        TestResult::Fail(
            "Authenticator did not return 'OK' response for GetInfo in extended form and ne=256",
        )
    }
}

/// Checks whether the card is checking the provided AID length when testing
/// against its own applet, by selecting applets with extra bytes after the real
/// AID.
///
/// Yubikey 5 NFC fails this test.
fn test_incorrect_aid(card: &NFCCard) -> TestResult {
    // Prepare a buffer with extra junk
    let mut aid = [0xFF; 16];
    aid[..APPLET_DF.len()].copy_from_slice(&APPLET_DF);

    for l in APPLET_DF.len() + 1..aid.len() {
        let resp = card
            .transmit(&select_by_df_name(&aid[..l]), &ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

        if resp.is_ok() {
            return TestResult::Fail("Selecting applet DF with extra bytes unexpectedly succeeded");
        }
    }

    TestResult::Pass
}

/// Ensure the card sends back no response when Ne=0 (expected response bytes).
///
/// ISO 7816-4 states that the number of response bytes in the data field "shall
/// be less than or equal to N<sub>e</sub>". Therefore, returning **any** bytes
/// for N<sub>e</sub> = 0 is an error: instead the card should return `61 xx`
/// with what N<sub>e</sub> we should use.
///
/// However, FIDO v1.x use a ISO 7816-4:2005-like APDU structure, even over
/// non-smartcard transport layers, but has several errors which affect use over
/// an ISO 7816 transport layer.
///
/// FIDO v1.0 NFC BT Amendment's "Raw Message Formats" acknowledges it is based
/// on ISO 7816-4:2005, but doesn't mention N<sub>e</sub>/L<sub>e</sub> at all,
/// and suggests a N<sub>c</sub> of up to `2^24` bytes (instead of `2^16`
/// bytes).
///
/// FIDO v1.0 "NFC Protocol" mentions L<sub>e</sub>, but gives incomplete
/// details, and then says "messages sent to an NFC authenticator SHALL follow
/// the U2F raw message format defined in (Raw Message Formats)" – which would
/// (erroneously) suggest L<sub>e</sub> is _not_ required.
///
/// FIDO v1.1 and later explicitly reference N<sub>e</sub>/L<sub>e</sub> in a
/// way that is _nearly_ consistent with ISO 7816-4: but only suggests that
/// N<sub>e</sub> = 0 "may" be used if an instruction "is not expected to yield
/// any response bytes". There are no explicit expectations about what happens
/// if there _are_ response bytes for a command with N<sub>e</sub> = 0; though
/// it mentions ISO 7816-4 command chaining as a way to fetch incomplete
/// responses in short form.
///
/// FIDO v2.0 and later explicitly delegate to ISO/IEC 7816-4 for the framing
/// format, but the CTAP1/U2F interoperability section indicates an
/// N<sub>c</sub> of up to `2^24` bytes and no N<sub>e</sub>, like FIDO v1.
fn test_select_zero_ne(card: &NFCCard) -> TestResult {
    let mut req = select_by_df_name(&APPLET_DF);
    req.ne = 0;
    let resp = card
        .transmit(&req, &ISO7816LengthForm::ShortOnly)
        .expect("Failed to select applet");

    if !resp.is_success() {
        return TestResult::Fail("Selecting CTAP applet should always give success");
    }

    if resp.ctap_needs_get_response() {
        return TestResult::Fail(
            "Card responded to interindustry SELECT command with NFCCTAP_GETRESPONSE expectation",
        );
    }

    if !resp.data.is_empty() {
        // We got some data back.
        // This suggests the card is reading the command buffer out of bounds.
        return TestResult::Fail("Expected no response data for Ne=0, card is reading from the command buffer out of bounds!");
    }

    if resp.bytes_available() == 0 {
        return TestResult::Fail("Card didn't report a corrected response length");
    }

    // Repeat with correct length
    req.ne = resp.bytes_available();
    let resp = card
        .transmit(&req, &ISO7816LengthForm::ShortOnly)
        .expect("Failed to select applet");

    if !resp.is_ok() {
        // Correct Ne should have worked?
        return TestResult::Fail("Selecting with correct Ne should succeed");
    }

    if req.ne as usize != resp.data.len() {
        // Incorrect extra bytes
        TestResult::Fail("Corrected response length wasn't correct")
    } else {
        TestResult::Pass
    }
}

fn test_select_truncation(card: &NFCCard) -> TestResult {
    let mut req = select_by_df_name(&APPLET_DF);
    let mut true_len: usize = 0;

    for ne in 1..256 {
        req.ne = ne;
        let resp = card.transmit(&req, &ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

        if !resp.is_success() {
            // We should always get a success response...
            return TestResult::Fail("Selecting applet with short Ne should succeed");
        }

        if resp.data.len() > ne {
            // Limit
            return TestResult::Fail("Card responded with too many bytes for Ne");
        }

        if resp.bytes_available() > 0 {
            if true_len == 0 {
                true_len = ne + resp.bytes_available();
            } else if true_len != ne + resp.bytes_available() {
                // changed mind
                return TestResult::Fail("Card changed Ne between commands");
            }
        } else {
            // We reached the end
            break;
        }
    }

    TestResult::Pass
}

fn test_card(card: NFCCard) {
    info!("Card detected ...");
    // Check that we're not a storage card
    if card.atr.storage_card {
        panic!("Detected storage card - only FIDO2 tokens are supported");
    }

    // Try to select the applet in short form.
    let resp = card
        .transmit(
            &select_by_df_name(&APPLET_DF),
            &ISO7816LengthForm::ShortOnly,
        )
        .expect("Failed to select applet");
    if !resp.is_ok() {
        panic!("Could not select FIDO2 applet, is this a FIDO2 token?");
    }

    const TESTS: [(&str, Test); 5] = [
        ("Select applet with extended Lc/Le", test_extended_lc_select),
        ("Select incorrect applet AID", test_incorrect_aid),
        ("Select with zero Ne", test_select_zero_ne),
        ("Select with truncated Ne", test_select_truncation),
        (
            "Get authenticator info with extended Le",
            test_extended_lc_info,
        ),
    ];

    let mut passes: Vec<&str> = Vec::with_capacity(TESTS.len());
    let mut skips: Vec<(&str, &str)> = Vec::with_capacity(TESTS.len());
    let mut failures: Vec<(&str, &str)> = Vec::with_capacity(TESTS.len());

    for (name, testfn) in &TESTS {
        println!("Started test: {}", name);
        let res = testfn(&card);
        println!("Finished test: {}, Result: {:?}", name, res);

        match res {
            TestResult::Pass => passes.push(name),
            TestResult::Skipped(m) => skips.push((name, m)),
            TestResult::Fail(m) => failures.push((name, m)),
        }
    }

    println!("# Conformance tests finished!");
    println!();
    println!("{:?}", card.atr);
    match card.atr.card_issuers_data_str() {
        Some(s) => println!("Card issuer's data: {}", s),
        None => {
            if let Some(d) = card.atr.card_issuers_data {
                println!("Card issuer's data: {:02x?}", d);
            }
        }
    }
    println!();
    println!("## {}/{} tests passed:", passes.len(), TESTS.len());
    println!();
    for n in passes {
        println!("* {}", n);
    }
    println!();
    if !skips.is_empty() {
        println!("## {}/{} tests skipped:", skips.len(), TESTS.len());
        println!();
        for (n, m) in skips {
            println!("* {} ({})", n, m);
        }
        println!();
    }
    if failures.is_empty() {
        println!("## No tests failed!");
    } else {
        println!("## {}/{} tests failed:", failures.len(), TESTS.len());
        println!();
        for (n, m) in failures {
            println!("* {} ({})", n, m);
        }
    }
    println!();
    println!("Tip: run with `RUST_LOG=trace` to see raw APDUs");
}

pub(crate) fn main() {
    let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    let card = reader.wait_for_card().expect("Error getting card");
    test_card(card);
}
