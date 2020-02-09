use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
// use openssl::ec::{EcKey, EcGroup};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};

use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};

pub fn generate_dyn_ssl_params(domain: &str) -> SslAcceptorBuilder {
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

    let key = &dyn_pkey;
    // Now setup the builder for them ...
    // For a file based setup, use this.
    /*
    .set_private_key_file(private_key_path, SslFiletype::PEM)
    .expect("Failed to add private key")
    .set_certificate_chain_file(cert_chain_path)
    .expect("Failed to add ca chain")
    */

    let mut ssl_builder =
        SslAcceptor::mozilla_modern(SslMethod::tls()).expect("Failed to setup acceptor");
    ssl_builder
        .set_private_key(&key)
        .expect("Failed to add pkey");
    ssl_builder
        .set_certificate(&cert)
        .expect("Failed to add leaf certificate");
    ssl_builder
}
