use webauthn_authenticator_rs::nfc::*;

#[derive(Debug)]
enum TestResult {
    Skipped(&'static str),
    Pass,
    Fail(&'static str),
}

type Test = fn(&NFCCard) -> TestResult;

/// For cards which declare support for extended Lc/Le, check that they actually
/// support it.
fn test_extended_lc(card: &NFCCard) -> TestResult {
    if card.atr.extended_lc != Some(true) {
        return TestResult::Skipped("Card does not support extended Lc/Le");
    }

    // Test with Le = 256 in extended mode
    let resp = card
        .transmit(
            &select_by_df_name(&APPLET_DF),
            ISO7816LengthForm::ExtendedOnly,
        )
        .expect("Failed to select applet");

    // Check error codes
    if resp.is_ok() {
        TestResult::Pass
    } else {
        TestResult::Fail("Card reports supporting extended Lc/Le, but doesn't")
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
            .transmit(&select_by_df_name(&aid[..l]), ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

        if resp.is_ok() {
            return TestResult::Fail("Selecting applet DF with extra bytes unexpectedly succeeded");
        }
    }

    TestResult::Pass
}

fn test_select_zero_ne(card: &NFCCard) -> TestResult {
    let mut req = select_by_df_name(&APPLET_DF);
    req.ne = 0;
    let resp = card
        .transmit(&req, ISO7816LengthForm::ShortOnly)
        .expect("Failed to select applet");

    if !resp.is_success() {
        return TestResult::Fail("Selecting CTAP applet should always give success");
    }

    if resp.ctap_needs_get_response() {
        return TestResult::Fail(
            "Card responded to interindustry SELECT command with NFCCTAP_GETRESPONSE expectation",
        );
    }

    if resp.data.len() > 0 {
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
        .transmit(&req, ISO7816LengthForm::ShortOnly)
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
        let resp = card
            .transmit(&req, ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

        if !resp.is_success() {
            // We should always get a success response...
            return TestResult::Fail("Selecting applet with short Ne should succeed");
        }

        if resp.data.len() > ne.into() {
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
        .transmit(&select_by_df_name(&APPLET_DF), ISO7816LengthForm::ShortOnly)
        .expect("Failed to select applet");
    if !resp.is_ok() {
        panic!("Could not select FIDO2 applet, is this a FIDO2 token?");
    }

    const TESTS: [(&str, Test); 4] = [
        ("Select applet with extended Lc/Le", test_extended_lc),
        ("Select incorrect applet AID", test_incorrect_aid),
        ("Select with zero Ne", test_select_zero_ne),
        ("Select with truncated Ne", test_select_truncation),
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
    println!("");
    println!("{:?}", card.atr);
    match card.atr.card_issuers_data_str() {
        Some(s) => println!("Card issuer's data: {}", s),
        None => match card.atr.card_issuers_data {
            Some(d) => println!("Card issuer's data: {:02x?}", d),
            None => (),
        },
    }
    println!("");
    println!("## {}/{} tests passed:", passes.len(), TESTS.len());
    println!("");
    for n in passes {
        println!("* {}", n);
    }
    println!("");
    if skips.len() > 0 {
        println!("## {}/{} tests skipped:", skips.len(), TESTS.len());
        println!("");
        for (n, m) in skips {
            println!("* {} ({})", n, m);
        }
        println!("");
    }
    if failures.len() == 0 {
        println!("## No tests failed!");
    } else {
        println!("## {}/{} tests failed:", failures.len(), TESTS.len());
        println!("");
        for (n, m) in failures {
            println!("* {} ({})", n, m);
        }
    }
    println!("");
    println!("Tip: run with `RUST_LOG=trace` to see raw APDUs");
}

pub(crate) fn main() {
    let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    let card = reader.wait_for_card().expect("Error getting card");
    test_card(card);
}
