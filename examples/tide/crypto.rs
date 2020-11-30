use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};

use rustls::{internal::pemfile, ServerConfig};

use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};

pub fn generate_dyn_ssl_config(domain: &str) -> ServerConfig {
    // I think this doesn't work yet 2019-07-26
    // TODO: Is this the correct curve choice?
    /*
    let dyn_ecgroup = EcGroup::from_curve_name(Nid::SECP384R1).expect("Failed to generate EcGroup");
    let dyn_eckey = EcKey::generate(&dyn_ecgroup).expect("Failed to generate EcKey");
    let dyn_pkey = PKey::from_ec_key(dyn_eckey).expect("Failed to extract private/public key");
    */

    let rsa = Rsa::generate(2048).unwrap();
    let dyn_pkey = PKey::from_rsa(rsa).unwrap();

    // Gen the alt/cn?

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, domain).unwrap();
    let name = name.build();

    // This has to be random to help prevent serial collision issues on accept
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

    let mut builder = X509::builder().unwrap();

    // Now setup ... lots of stuff for the x509 setup
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_subject_name(&name).unwrap();

    // Set the subject alt name, this is important!
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns(domain)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_alternative_name).unwrap();

    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(5).unwrap())
        .unwrap();
    builder.set_pubkey(&dyn_pkey).unwrap();

    /* How much of this is needed? --v */
    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .other("2.999.1")
        .build()
        .unwrap();
    builder.append_extension(ext_key_usage).unwrap();
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_key_identifier).unwrap();
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(authority_key_identifier).unwrap();
    /* How much of this is needed? --^ */

    // Now sign with the pkey. Is this the best digest type?
    builder.sign(&dyn_pkey, MessageDigest::sha256()).unwrap();

    let cert: X509 = builder.build();

    let mut pkey_bytes: &[u8] = &dyn_pkey.private_key_to_pem_pkcs8().unwrap();
    let mut cert_bytes: &[u8] = &cert.to_pem().unwrap();

    let rustls_pkey = pemfile::pkcs8_private_keys(&mut pkey_bytes)
        .unwrap()
        .pop()
        .unwrap();
    let rustls_certs = pemfile::certs(&mut cert_bytes).unwrap();

    let mut server_config = ServerConfig::new(rustls::NoClientAuth::new());
    server_config
        .set_single_cert(rustls_certs, rustls_pkey)
        .unwrap();

    server_config
}
