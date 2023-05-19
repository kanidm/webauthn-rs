//! Abstraction to merge all available transports for the platform.
//!
//! This is still a work in progress, and doesn't yet handle tokens quite as
//! well as we'd like.
use futures::StreamExt;
use tokio::sync::mpsc;

#[cfg(any(all(doc, not(doctest)), feature = "bluetooth"))]
use crate::bluetooth::*;
#[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
use crate::nfc::*;
use crate::transport::*;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
use crate::usb::*;

/// [AnyTransport] merges all available transports for the platform.
#[derive(Debug)]
pub struct AnyTransport {
    #[cfg(any(all(doc, not(doctest)), feature = "bluetooth"))]
    pub bluetooth: BluetoothTransport,
    #[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
    pub nfc: Option<NFCReader>,
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    pub usb: USBTransport,
}

/// [AnyToken] abstracts calls to physical authenticators.
#[derive(Debug)]
pub enum AnyToken {
    /// No-op stub entry, never used.
    Stub,
    #[cfg(any(all(doc, not(doctest)), feature = "bluetooth"))]
    Bluetooth(BluetoothToken),
    #[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
    Nfc(NFCCard),
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    Usb(USBToken),
}

#[derive(Debug)]
pub enum AnyTokenId {
    /// No-op stub entry, never used.
    Stub,
    #[cfg(any(all(doc, not(doctest)), feature = "bluetooth"))]
    Bluetooth(()),
    #[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
    Nfc(()),
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    Usb(<USBToken as Token>::Id),
}


impl AnyTransport {
    /// Creates connections to all available transports.
    ///
    /// For NFC, uses `Scope::User`, and [ignores unavailability of the PC/SC
    /// Service][0].
    ///
    /// [0]: crate::nfc#smart-card-service
    pub async fn new() -> Result<Self, WebauthnCError> {
        Ok(AnyTransport {
            #[cfg(feature = "bluetooth")]
            bluetooth: BluetoothTransport::new().await?,
            #[cfg(feature = "nfc")]
            nfc: match NFCReader::new(pcsc::Scope::User) {
                Ok(reader) => Some(reader),
                Err(WebauthnCError::PcscError(pcsc::Error::NoService))
                | Err(WebauthnCError::PcscError(pcsc::Error::ServiceStopped)) => {
                    warn!("PC/SC service not available, continuing without NFC support...");
                    None
                }
                Err(e) => return Err(e),
            },
            #[cfg(feature = "usb")]
            usb: USBTransport::new()?,
        })
    }
}

#[async_trait]
impl<'b> Transport<'b> for AnyTransport {
    type Token = AnyToken;

    #[allow(unreachable_code)]
    async fn watch_tokens(&mut self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError> {
        #[cfg(not(any(feature = "bluetooth", feature = "nfc", feature = "usb")))]
        {
            error!("No transports available!");
            return Err(WebauthnCError::NotSupported);
        }

        // let mut o: Vec<Self::Token> = Vec::new();

        // #[cfg(feature = "bluetooth")]
        // o.extend(
        //     self.bluetooth
        //         .tokens()
        //         .await?
        //         .into_iter()
        //         .map(AnyToken::Bluetooth),
        // );

        // #[cfg(feature = "nfc")]
        // if let Some(nfc) = &mut self.nfc {
        //     o.extend(nfc.tokens().await?.into_iter().map(AnyToken::Nfc));
        // }

        
        #[cfg(feature = "usb")]
        {
            let s = self.usb.watch_tokens().await?;
            return Ok(Box::pin(s.map(|e| {
                match e {
                    TokenEvent::Added(u) => TokenEvent::Added(AnyToken::Usb(u)),
                    TokenEvent::Removed(u) => TokenEvent::Removed(AnyTokenId::Usb(u)),
                    // TODO: wait for all transports to report enumeration complete before actually firing this
                    TokenEvent::EnumerationComplete => TokenEvent::EnumerationComplete,
                }
            })));
            // o.extend(self.usb.tokens().await?.into_iter().map(AnyToken::Usb));
        }
        // Ok(o)

        todo!()
    }

}

#[async_trait]
#[allow(clippy::unimplemented)]
impl Token for AnyToken {
    type Id = AnyTokenId;

    #[allow(unused_variables)]
    async fn transmit_raw<U>(&mut self, cmd: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => Token::transmit_raw(b, cmd, ui).await,
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => Token::transmit_raw(n, cmd, ui).await,
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => Token::transmit_raw(u, cmd, ui).await,
        }
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => b.init().await,
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.init().await,
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.init().await,
        }
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => b.close().await,
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.close().await,
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.close().await,
        }
    }

    fn get_transport(&self) -> AuthenticatorTransport {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => b.get_transport(),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.get_transport(),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_transport(),
        }
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => b.cancel().await,
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.cancel().await,
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.cancel().await,
        }
    }

    fn has_button(&self) -> bool {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(b) => b.has_button(),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.has_button(),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.has_button(),
        }
    }
}
