use crate::prelude::*;

// Yubico root cert.
// https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
pub const YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----";

impl DataBuilder {
    pub fn add_yubico(mut self) -> Self {
        let yk_mfr = Rc::new(Manufacturer {
            display_name: "Yubico".to_string(),
        });

        // https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
        let yk_ca = Rc::new(Authority {
            ca: x509::X509::from_pem(YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM).expect("Invalid DER"),
        });

        // YK 5 FIPS
        let yk_5_fips_aaguid = Rc::new(Aaguid {
            id: uuid::uuid!("73bb0cd4-e502-49b8-9c6f-b59445bf720b"),
            ca: vec![yk_ca.clone()],
        });

        let yk_5_fips_sku_5_4_3 = Rc::new(Sku {
            display_name: "YubiKey 5 FIPS Series".to_string(),
            version: "5.4.3".to_string(),
        });

        // device
        let yk_5_fips = Rc::new(Device {
            aaguid: yk_5_fips_aaguid,
            skus: vec![yk_5_fips_sku_5_4_3],
            mfr: yk_mfr.clone(),
            // default
            images: Vec::default(),
            quirks: BTreeSet::default(),
        });

        self.devices.push(yk_5_fips);

        // YK 5 bio series
        let yk_5_bio_aaguid = Rc::new(Aaguid {
            id: uuid::uuid!("d8522d9f-575b-4866-88a9-ba99fa02f35b"),
            ca: vec![yk_ca.clone()],
        });

        let yk_5_bio_sku_5_5_6 = Rc::new(Sku {
            display_name: "YubiKey Bio Series".to_string(),
            version: "5.5.6".to_string(),
        });

        let yk_5_bio = Rc::new(Device {
            aaguid: yk_5_bio_aaguid,
            skus: vec![yk_5_bio_sku_5_5_6],
            mfr: yk_mfr.clone(),
            // default
            images: Vec::default(),
            quirks: BTreeSet::default(),
        });

        self.devices.push(yk_5_bio);

        self
    }
}
