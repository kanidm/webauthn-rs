//! Abstraction to merge all available transports for the platform.
//!
//! This is still a work in progress, and doesn't yet handle tokens quite as
//! well as we'd like.
#[cfg(doc)]
use crate::stubs::*;

use async_stream::stream;
use futures::{stream::FusedStream, StreamExt};

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
    pub nfc: Option<NFCTransport>,
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
    Bluetooth(<BluetoothToken as Token>::Id),
    #[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
    Nfc(<NFCCard as Token>::Id),
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
            nfc: match NFCTransport::new(pcsc::Scope::User) {
                Ok(reader) => Some(reader),
                Err(e) => {
                    warn!("PC/SC service not available ({e:?}), continuing without NFC support...");
                    None
                }
            },
            #[cfg(feature = "usb")]
            usb: USBTransport::new().await?,
        })
    }
}

#[async_trait]
impl Transport<'_> for AnyTransport {
    type Token = AnyToken;

    #[allow(unreachable_code)]
    async fn watch(&self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError> {
        // Bluetooth
        let mut bluetooth_complete = !cfg!(feature = "bluetooth");
        #[cfg(feature = "bluetooth")]
        let bluetooth: BoxStream<TokenEvent<BluetoothToken>> = match self.bluetooth.watch().await {
            Err(e) => {
                error!("Bluetooth transport failure: {e:?}");
                bluetooth_complete = true;
                Box::pin(futures::stream::empty())
            }
            Ok(s) => s,
        };

        #[cfg(not(feature = "bluetooth"))]
        let bluetooth: BoxStream<TokenEvent<AnyToken>> = Box::pin(futures::stream::empty());

        let mut bluetooth = bluetooth.fuse();

        // NFC
        let mut nfc_complete = !cfg!(feature = "nfc");
        #[cfg(feature = "nfc")]
        let nfc: BoxStream<TokenEvent<NFCCard>> = if let Some(nfc) = &self.nfc {
            match nfc.watch().await {
                Err(e) => {
                    error!("NFC transport failure: {e:?}");
                    nfc_complete = true;
                    Box::pin(futures::stream::empty())
                }
                Ok(s) => s,
            }
        } else {
            nfc_complete = true;
            Box::pin(futures::stream::empty())
        };

        #[cfg(not(feature = "nfc"))]
        let nfc: BoxStream<TokenEvent<AnyToken>> = Box::pin(futures::stream::empty());

        let mut nfc = nfc.fuse();

        // USB HID
        let mut usb_complete = !cfg!(feature = "usb");
        #[cfg(feature = "usb")]
        let usb: BoxStream<TokenEvent<USBToken>> = match self.usb.watch().await {
            Err(e) => {
                error!("USB transport failure: {e:?}");
                usb_complete = true;
                Box::pin(futures::stream::empty())
            }
            Ok(s) => s,
        };

        #[cfg(not(feature = "usb"))]
        let usb: BoxStream<TokenEvent<AnyToken>> = Box::pin(futures::stream::empty());

        let mut usb = usb.fuse();

        if bluetooth_complete && nfc_complete && usb_complete {
            error!("no transports available!");
            return Err(WebauthnCError::NotSupported);
        }

        // Main stream
        let s = stream! {
            #[cfg(not(doc))]
            while !bluetooth.is_terminated() || !nfc.is_terminated() || !usb.is_terminated() {
                tokio::select! {
                    Some(b) = bluetooth.next() => {
                        #[cfg(feature = "bluetooth")]
                        let b: TokenEvent<AnyToken> = b.into();
                        if matches!(b, TokenEvent::EnumerationComplete) {
                            if nfc_complete && usb_complete {
                                trace!("Sending enumeration complete from Bluetooth");
                                yield TokenEvent::EnumerationComplete;
                            }
                            bluetooth_complete = true;
                        } else {
                            yield b;
                        }
                    }

                    Some(n) = nfc.next() => {
                        #[cfg(feature = "nfc")]
                        let n: TokenEvent<AnyToken> = n.into();
                        if matches!(n, TokenEvent::EnumerationComplete) {
                            if bluetooth_complete && usb_complete {
                                trace!("Sending enumeration complete from NFC");
                                yield TokenEvent::EnumerationComplete;
                            }
                            nfc_complete = true;
                        } else {
                            yield n;
                        }
                    }

                    Some(u) = usb.next() => {
                        #[cfg(feature = "usb")]
                        let u: TokenEvent<AnyToken> = u.into();
                        if matches!(u, TokenEvent::EnumerationComplete) {
                            if bluetooth_complete && nfc_complete {
                                trace!("Sending enumeration complete from USB");
                                yield TokenEvent::EnumerationComplete;
                            }
                            usb_complete = true;
                        } else {
                            yield u;
                        }
                    }

                    else => continue,
                }
            }
        };

        Ok(Box::pin(s))
    }

    #[allow(unreachable_code)]
    async fn tokens(&self) -> Result<Vec<Self::Token>, WebauthnCError> {
        #[cfg(not(any(feature = "bluetooth", feature = "nfc", feature = "usb")))]
        {
            error!("No transports available!");
            return Err(WebauthnCError::NotSupported);
        }

        let mut o: Vec<Self::Token> = Vec::new();

        #[cfg(feature = "bluetooth")]
        o.extend(
            self.bluetooth
                .tokens()
                .await?
                .into_iter()
                .map(AnyToken::Bluetooth),
        );

        #[cfg(feature = "nfc")]
        if let Some(nfc) = &self.nfc {
            o.extend(nfc.tokens().await?.into_iter().map(AnyToken::Nfc));
        }

        #[cfg(feature = "usb")]
        o.extend(self.usb.tokens().await?.into_iter().map(AnyToken::Usb));

        Ok(o)
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

#[cfg(feature = "bluetooth")]
impl From<TokenEvent<BluetoothToken>> for TokenEvent<AnyToken> {
    fn from(e: TokenEvent<BluetoothToken>) -> Self {
        match e {
            TokenEvent::Added(t) => TokenEvent::Added(AnyToken::Bluetooth(t)),
            TokenEvent::Removed(i) => TokenEvent::Removed(AnyTokenId::Bluetooth(i)),
            TokenEvent::EnumerationComplete => TokenEvent::EnumerationComplete,
        }
    }
}

#[cfg(feature = "nfc")]
impl From<TokenEvent<NFCCard>> for TokenEvent<AnyToken> {
    fn from(e: TokenEvent<NFCCard>) -> Self {
        match e {
            TokenEvent::Added(t) => TokenEvent::Added(AnyToken::Nfc(t)),
            TokenEvent::Removed(i) => TokenEvent::Removed(AnyTokenId::Nfc(i)),
            TokenEvent::EnumerationComplete => TokenEvent::EnumerationComplete,
        }
    }
}

#[cfg(feature = "usb")]
impl From<TokenEvent<USBToken>> for TokenEvent<AnyToken> {
    fn from(e: TokenEvent<USBToken>) -> Self {
        match e {
            TokenEvent::Added(t) => TokenEvent::Added(AnyToken::Usb(t)),
            TokenEvent::Removed(i) => TokenEvent::Removed(AnyTokenId::Usb(i)),
            TokenEvent::EnumerationComplete => TokenEvent::EnumerationComplete,
        }
    }
}
