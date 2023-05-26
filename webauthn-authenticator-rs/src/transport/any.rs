//! Abstraction to merge all available transports for the platform.
//!
//! This is still a work in progress, and doesn't yet handle tokens quite as
//! well as we'd like.
use async_stream::stream;
use futures::{
    select,
    stream::{select_all, Empty, FusedStream},
    StreamExt, select_biased,
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

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
    Bluetooth(()),
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
                Err(WebauthnCError::PcscError(pcsc::Error::NoService))
                | Err(WebauthnCError::PcscError(pcsc::Error::NoAccess))
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

        let s = stream! {

            let mut nfc_complete = false;
            let nfc: BoxStream<TokenEvent<NFCCard>> = if let Some(nfc) = &mut self.nfc {
                match nfc.watch_tokens().await {
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
            let mut nfc = nfc.fuse();

            let mut usb_complete = false;
            let mut usb = self.usb.watch_tokens().await.unwrap().fuse();

            
            while !nfc.is_terminated() || !usb.is_terminated() {
                tokio::select! {
                    Some(u) = usb.next() => {
                        match u {
                            TokenEvent::Added(u) => {yield TokenEvent::Added(AnyToken::Usb(u));},
                            TokenEvent::Removed(i) => {yield TokenEvent::Removed(AnyTokenId::Usb(i));},
                            TokenEvent::EnumerationComplete => {
                                if nfc_complete {
                                    trace!("Sending enumeration complete from USB");
                                    yield TokenEvent::EnumerationComplete;
                                }
                                usb_complete = true;
                            }
                        }
                    }

                    Some(n) = nfc.next() => {
                        trace!("NFC event: {n:?}");

                        match n {
                            TokenEvent::Added(n) => { yield TokenEvent::Added(AnyToken::Nfc(n)); }
                            TokenEvent::Removed(i) => {yield TokenEvent::Removed(AnyTokenId::Nfc(i));},
                            TokenEvent::EnumerationComplete => {
                                if usb_complete {
                                    trace!("Sending enumeration complete from NFC");
                                    yield TokenEvent::EnumerationComplete;
                                }
                                nfc_complete = true;
                            }
                        }
                    }
                    
                }
            }
        };

        Ok(Box::pin(s))
/*
        let (enumeration_tx, enumeration_rx) = mpsc::channel(1);
        let enumeration_stream = Box::pin(ReceiverStream::new(enumeration_rx));
        let (nfc_tx, mut nfc_rx) = mpsc::channel(1);
        let (usb_tx, mut usb_rx) = mpsc::channel(1);

        let usb: BoxStream<TokenEvent<Self::Token>> =
            Box::pin(self.usb.watch_tokens().await?.filter_map(|e| async move {
                match e {
                    TokenEvent::Added(u) => Some(TokenEvent::Added(AnyToken::Usb(u))),
                    TokenEvent::Removed(u) => Some(TokenEvent::Removed(AnyTokenId::Usb(u))),
                    TokenEvent::EnumerationComplete => {
                        usb_tx.clone().send(());
                        None
                    }
                }
            }));

        tokio::spawn(async move {
            // We don't actually care about the result, only that enumeration
            // finished.
            let _ = nfc_rx.recv().await;
            let _ = usb_rx.recv().await;
            enumeration_tx.send(TokenEvent::EnumerationComplete);
            todo!()
        });

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

        Ok(Box::pin(select_all([nfc, usb, enumeration_stream])))
         */
    }

    async fn get_devices(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        #[cfg(not(any(feature = "bluetooth", feature = "nfc", feature = "usb")))]
        {
            error!("No transports available!");
            return Err(WebauthnCError::NotSupported);
        }

        let mut o: Vec<Self::Token> = Vec::new();

        #[cfg(feature = "bluetooth")]
        o.extend(
            self.bluetooth
                .get_devices()
                .await?
                .into_iter()
                .map(AnyToken::Bluetooth),
        );

        #[cfg(feature = "nfc")]
        if let Some(nfc) = &mut self.nfc {
            o.extend(nfc.get_devices().await?.into_iter().map(AnyToken::Nfc));
        }

        #[cfg(feature = "usb")]
        o.extend(self.usb.get_devices().await?.into_iter().map(AnyToken::Usb));

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
