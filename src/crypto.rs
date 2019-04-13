use openssl::{bn, ec, nid};
use std::convert::TryFrom;

use super::constants::*;
use super::proto::*;

// Why OpenSSL over another rust crate?
// - Well, the openssl crate allows us to reconstruct a public key from the
//   x/y group coords, where most others want a pkcs formatted structure. As
//   a result, it's easiest to use openssl as it gives us exactly what we need
//   for these operations, and despite it's many challenges as a library, it
//   has resources and investment into it's maintenance, so we can a least
//   assert a higher level of confidence in it that <backyard crypto here>.

// Object({Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]), Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]), Integer(-1): U64(1), Integer(1): U64(2), Integer(3): I64(-7)})
//

#[derive(Debug)]
pub enum Algorithm {
    ALG_ECDSA_SHA256,
    ALG_RSASSA_PKCS15_SHA256,
    ALG_RSASSA_PSS_SHA256,
}

impl From<&Algorithm> for i16 {
    fn from(a: &Algorithm) -> i16 {
        match a {
            ALG_ECDSA_SHA256 => -7,
            ALG_RSASSA_PKCS15_SHA256 => -257,
            ALG_RSASSA_PSS_SHA256 => -37,
        }
    }
}

// Could make this a cbor option key type to save some boiler plate?
impl TryFrom<i64> for Algorithm {
    type Error = ();
    fn try_from(i: i64) -> Result<Algorithm, Self::Error> {
        match i {
            -7 => Ok(Algorithm::ALG_ECDSA_SHA256),
            _ => Err(()),
        }
    }
}

pub(crate) fn verify_attestation_sig(
    acd: &AttestedCredentialData,
    data: &Vec<u8>,
) -> Result<(), ()> {
    // Now, they say to get the alg, which we do from the alg
    // which is in the authData.acd.credential_pk;
    // The credential_pk is in "COSE_Key format" apparently
    // which is documented here
    // https://www.rfc-editor.org/rfc/rfc8152.txt
    // which means that alg is in optional field keyd 3 in the map.

    let cred_pk = match acd.credential_pk.as_object() {
        Some(cred_pk) => cred_pk,
        None => {
            println!("ACD cbor not usable as map");
            return Err(());
        }
    };

    let alg_id = match cred_pk.get(&serde_cbor::ObjectKey::Integer(3)) {
        Some(id) => match id.as_i64() {
            Some(i) => i,
            None => {
                println!("ALG ID Was not an integer!?");
                return Err(());
            }
        },
        None => {
            println!("No ALG ID present");
            return Err(());
        }
    };

    let alg_enum = match Algorithm::try_from(alg_id) {
        Ok(a) => a,
        Err(e) => {
            println!("Alg ID not understood by our code ... {:?}", e);
            return Err(e);
        }
    };

    println!("Selected alg id {:?}", alg_enum);

    // Verify stuff meow.
    // https://medium.com/@herrjemand/verifying-fido2-packed-attestation-a067a9b2facd

    // Based on the attest_fmt, that changes the data we need to attest

    match alg_enum {
        ALG_ECDSA_SHA256 => {
            // Right, we need to get various bits out now for this next function to work.
            //
            // verify_ecdsa_sha256()
            unimplemented!()
        }
        ALG_RSASSA_PKCS15_SHA256 => unimplemented!(),
        ALG_RSASSA_PSS_SHA256 => unimplemented!(),
    }
}

fn verify_ecdsa_sha256(
    kty: u64,      // This is the key type
    x: &[u8],      // The X point
    y: &[u8],      // The Y point
    groupref: u64, // The curve to use
    data: &Vec<u8>,
) -> Result<(), ()> {
    // you need the key type. Check value 1 (kty) frmo cred_pk, and compare to:
    //
    // +---------+-------+----------+------------------------------------+
    // | Name    | Value | Key Type | Description                        |
    // +---------+-------+----------+------------------------------------+
    // | P-256   | 1     | EC2      | NIST P-256 also known as secp256r1 |
    // | P-384   | 2     | EC2      | NIST P-384 also known as secp384r1 |
    // | P-521   | 3     | EC2      | NIST P-521 also known as secp521r1 |
    // | X25519  | 4     | OKP      | X25519 for use w/ ECDH only        |
    // | X448    | 5     | OKP      | X448 for use w/ ECDH only          |
    // | Ed25519 | 6     | OKP      | Ed25519 for use w/ EdDSA only      |
    // | Ed448   | 7     | OKP      | Ed448 for use w/ EdDSA only        |
    // +---------+-------+----------+------------------------------------+
    // In the case I have here, my key is 2, so secp384r1

    let xbn = bn::BigNum::from_slice(x).unwrap();
    let ybn = bn::BigNum::from_slice(y).unwrap();

    let group = ec::EcGroup::from_curve_name(nid::Nid::SECP384R1).unwrap();

    let ec_key = ec::EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
    assert!(ec_key.check_key().is_ok());
    // Check the x/y points are actually on the curve. Does check_key do this?

    Err(())
}
