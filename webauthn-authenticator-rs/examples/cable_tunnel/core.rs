use bluetooth_hci::{
    host::{
        uart::{CommandHeader, Hci as UartHci, Packet},
        AdvertisingFilterPolicy, AdvertisingParameters, Channels, Hci, OwnAddressType,
    },
    types::{Advertisement, AdvertisingInterval, AdvertisingType},
    BdAddr, BdAddrType,
};
use clap::{ArgGroup, Parser};
use openssl::rand::rand_bytes;
use serialport::FlowControl;
use serialport_hci::{
    vendor::none::{Event, Vendor},
    SerialController,
};
use std::{fmt::Debug, fs::OpenOptions, time::Duration};

use webauthn_authenticator_rs::{
    cable::{share_cable_authenticator, Advertiser},
    ctap2::CtapAuthenticator,
    error::WebauthnCError,
    softtoken::SoftTokenFile,
    transport::{AnyTransport, Transport},
    ui::Cli,
};

#[derive(Debug, clap::Parser)]
#[clap(about = "caBLE tunneler tool")]
#[clap(group(
    ArgGroup::new("url")
        .required(true)
        .args(&["cable-url", "qr-image"])
))]
pub struct CliParser {
    /// Serial port where Bluetooth HCI controller is connected to.
    ///
    /// This has primarily been tested using a Nordic nRF52 microcontroller
    /// running [Apache Mynewt's NimBLE HCI demo][0].
    ///
    /// [0]: https://mynewt.apache.org/latest/tutorials/ble/blehci_project.html
    #[clap(short, long)]
    pub serial_port: String,

    /// Baud rate for communication with Bluetooth HCI controller.
    ///
    /// By default, Apache Mynewt's NimBLE HCI demo runs at 1000000 baud.
    #[clap(short, long, default_value = "1000000")]
    pub baud_rate: u32,

    /// Tunnel server ID to use. 0 = Google.
    #[clap(short, long, default_value = "0")]
    pub tunnel_server_id: u16,

    /// `FIDO:/` URL from the initiator's QR code. Either this option or
    /// --qr-image is required.
    #[clap(short, long)]
    pub cable_url: Option<String>,

    /// Screenshot of the initator's QR code. Either this option or --cable-url
    /// is required.
    ///
    /// Use `adb` to screenshot an Android device with USB debugging:
    ///
    /// adb exec-out screencap -p > screenshot.png
    ///
    /// Use Xcode to screenshot an iOS device with debugging. There is no need
    /// to open an Xcode project: from the `Window` menu, select
    /// `Devices and Simulators`, then select the device, and press
    /// `Take Screenshot`. The screenshot will be saved to `~/Desktop`.
    ///
    /// Note: this *will not* work in the Android emulator or iOS simulator,
    /// because they do not have access to a physical Bluetooth controller.
    #[clap(short, long)]
    pub qr_image: Option<String>,

    /// Path to saved SoftToken.
    ///
    /// You can create a new SoftToken with the `softtoken` example:
    ///
    /// cargo run --example softtoken -- create /tmp/softtoken.dat
    ///
    /// If this option is not specified, `cable_tunnel` will attempt to connect
    /// to the first supported physical token using AnyTransport. Most initators
    /// (browsers) will *also* attempt to connect directly to *all* physical
    /// tokens, so only use this if your initator is running on another device!
    #[clap(long)]
    pub softtoken_path: Option<String>,
}

struct SerialHciAdvertiser {
    hci: SerialController<CommandHeader, Vendor>,
}

impl SerialHciAdvertiser {
    fn new(serial_port: &str, baud_rate: u32) -> Self {
        let port = serialport::new(serial_port, baud_rate)
            .timeout(Duration::from_secs(2))
            .flow_control(FlowControl::None)
            .open()
            .unwrap();
        Self {
            hci: SerialController::new(port),
        }
    }

    fn read(&mut self) -> Packet<Event> {
        let r = self.hci.read().unwrap();
        trace!("<<< {:?}", r);
        r
    }
}

impl Advertiser for SerialHciAdvertiser {
    fn stop_advertising(&mut self) -> Result<(), WebauthnCError> {
        trace!("sending reset...");
        self.hci.reset().unwrap();
        let _ = self.read();

        self.hci.le_set_advertise_enable(false).unwrap();
        let _ = self.read();
        Ok(())
    }

    fn start_advertising(
        &mut self,
        service_uuid: u16,
        payload: &[u8],
    ) -> Result<(), WebauthnCError> {
        self.stop_advertising()?;
        let advert = Advertisement::ServiceData16BitUuid(service_uuid, payload);
        let mut service_data = [0; 31];
        let len = advert.copy_into_slice(&mut service_data);

        let p = AdvertisingParameters {
            advertising_interval: AdvertisingInterval::for_type(
                AdvertisingType::NonConnectableUndirected,
            )
            .with_range(Duration::from_millis(100), Duration::from_millis(500))
            .unwrap(),
            own_address_type: OwnAddressType::Random,
            peer_address: BdAddrType::Random(bluetooth_hci::BdAddr([0xc0; 6])),
            advertising_channel_map: Channels::all(),
            advertising_filter_policy: AdvertisingFilterPolicy::WhiteListConnectionAllowScan,
        };
        let mut addr = [0u8; 6];
        addr[5] = 0xc0;
        rand_bytes(&mut addr[..5])?;

        self.hci.le_set_random_address(BdAddr(addr)).unwrap();
        let _ = self.read();

        self.hci.le_set_advertising_parameters(&p).unwrap();
        let _ = self.read();

        self.hci
            .le_set_advertising_data(&service_data[..len])
            .unwrap();
        let _ = self.read();

        self.hci.le_set_advertise_enable(true).unwrap();
        let _ = self.read();
        Ok(())
    }
}

#[tokio::main]
pub(super) async fn main() {
    let opt = CliParser::parse();
    let cable_url = if let Some(u) = opt.cable_url {
        u
    } else if let Some(img) = opt.qr_image {
        let img = image::open(img).unwrap();
        // Optimised for screenshots from the device.
        let img = img.adjust_contrast(9000.0);

        let decoder = bardecoder::default_decoder();
        let fido_url = decoder
            .decode(&img)
            .into_iter()
            .filter_map(|r| {
                trace!(?r);
                r.ok()
            })
            .find(|u| {
                trace!("Found QR code: {:?}", u);
                let u = u.to_ascii_uppercase();
                u.starts_with("FIDO:/")
            });
        match fido_url {
            Some(u) => u,
            None => {
                panic!("Could not find any FIDO URLs in the image");
            }
        }
    } else {
        unreachable!();
    };

    let mut advertiser = SerialHciAdvertiser::new(&opt.serial_port, opt.baud_rate);
    let ui = Cli {};

    if let Some(p) = opt.softtoken_path {
        // Use a SoftToken
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(p)
            .unwrap();
        let mut softtoken = SoftTokenFile::open(f).unwrap();
        let info = softtoken.as_ref().get_info();

        share_cable_authenticator(
            &mut softtoken,
            info,
            cable_url.trim(),
            opt.tunnel_server_id,
            &mut advertiser,
            &ui,
            true,
        )
        .await
        .unwrap();
    } else {
        // Use a physical authenticator
        let mut transport = AnyTransport::new().unwrap();
        let token = transport.tokens().unwrap().pop().unwrap();
        let mut authenticator = CtapAuthenticator::new(token, &ui).await.unwrap();
        let info = authenticator.get_info().to_owned();

        share_cable_authenticator(
            &mut authenticator,
            info,
            cable_url.trim(),
            opt.tunnel_server_id,
            &mut advertiser,
            &ui,
            true,
        )
        .await
        .unwrap();
    };
}
