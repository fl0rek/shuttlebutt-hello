#![allow(non_snake_case)] // we want to match names used in ssb documentation

use crate::connection::PeerConnection;
use pretty_hex::PrettyHex;
use sodiumoxide::crypto::{
    auth,
    hash::sha256,
    kx,
    scalarmult::{scalarmult, GroupElement, Scalar},
    secretbox,
    sign::{self, ed25519},
};
use std::io::{self, Read, Write};
use thiserror::Error;

const SHS_CLIENT_AUTHENTICATE_MESSAGE_LEN: usize = 112;
const SHS_SERVER_ACCEPT_MESSAGE_LEN: usize = 80;
const SHS_SERVER_HELLO_MESSAGE_LEN: usize = 64;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Server hello verification failed")]
    ServerHelloVerificationFailed,

    #[error("Invalid length error from sodiumoxide, should not happen")]
    SodiumoxideInvalidLength,

    //https://docs.rs/sodiumoxide/latest/sodiumoxide/crypto/scalarmult/curve25519/fn.scalarmult.html
    #[error("Tried to scalarmult with zero GroupElement")]
    ScalarMultZeroGroupElement,

    #[error("Unable to convert longterm keys from ed25519 to curve25519")]
    Ed25519ToCurve25519ConverstionFailed,

    #[error("Failed to decrypt server accept message")]
    ServerAcceptDecryptionFailed,

    #[error("Server accept message verification failed")]
    ServerAcceptVerificationFailed,

    // ssb-server severs the connection if validation fails during handshake, so we want to
    // distinguish this io::Error from others
    #[error("Connection interrupted: {0}")]
    ConnectionInterrupted(io::Error),

    #[error("Io error: {0}")]
    IoError(#[from] io::Error),
}

pub struct Handshake<State, C: Read + Write> {
    state: State,
    channel: C,
}

pub struct SendingClientHello {
    pub(crate) network_identifier: auth::Key,

    pub(crate) client_longterm_pk: ed25519::PublicKey,
    pub(crate) client_longterm_sk: ed25519::SecretKey,
    pub(crate) server_longterm_pk: ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    pub(crate) client_ephemeral_sk: kx::SecretKey,
}

impl From<SendingClientHello> for AwaitingServerHello {
    fn from(value: SendingClientHello) -> Self {
        Self {
            network_identifier: value.network_identifier,

            client_longterm_pk: value.client_longterm_pk,
            client_longterm_sk: value.client_longterm_sk,
            server_longterm_pk: value.server_longterm_pk,

            client_ephemeral_pk: value.client_ephemeral_pk,
            client_ephemeral_sk: value.client_ephemeral_sk,
        }
    }
}

pub struct AwaitingServerHello {
    pub(crate) network_identifier: auth::Key,

    pub(crate) client_longterm_pk: ed25519::PublicKey,
    pub(crate) client_longterm_sk: ed25519::SecretKey,
    pub(crate) server_longterm_pk: ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    pub(crate) client_ephemeral_sk: kx::SecretKey,
}

impl AwaitingServerHello {
    fn derive_shared_secret_ab(
        &self,
        server_ephemeral_pk: &kx::PublicKey,
    ) -> Result<GroupElement, HandshakeError> {
        let client_ephemeral_sk = Scalar::from_slice(self.client_ephemeral_sk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;
        let server_ephemeral_pk = GroupElement::from_slice(server_ephemeral_pk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        scalarmult(&client_ephemeral_sk, &server_ephemeral_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }

    fn derive_shared_secret_aB(&self) -> Result<GroupElement, HandshakeError> {
        let client_ephemeral_sk = Scalar::from_slice(self.client_ephemeral_sk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        // need to convert from ed25519 to curve25519
        let server_longterm_pk = ed25519::to_curve25519_pk(&self.server_longterm_pk)
            .map_err(|_| HandshakeError::Ed25519ToCurve25519ConverstionFailed)?;
        let server_longterm_pk = GroupElement(server_longterm_pk.0);

        scalarmult(&client_ephemeral_sk, &server_longterm_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }

    fn create_detached_signature_A(&self, shared_secret_ab: &GroupElement) -> sign::Signature {
        let signature_message = [
            self.network_identifier.as_ref(),
            self.server_longterm_pk.as_ref(),
            sha256::hash(shared_secret_ab.as_ref()).as_ref(),
        ]
        .concat();

        sign::sign_detached(&signature_message, &self.client_longterm_sk)
    }
}

pub struct SendingClientAuthenticate {
    pub(crate) network_identifier: auth::Key,

    pub(crate) client_longterm_pk: ed25519::PublicKey,
    pub(crate) client_longterm_sk: ed25519::SecretKey,
    pub(crate) server_longterm_pk: ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    //pub(crate) client_ephemeral_sk: kx::SecretKey,
    pub(crate) server_ephemeral_pk: kx::PublicKey,

    pub(crate) shared_secret_ab: GroupElement,
    pub(crate) shared_secret_aB: GroupElement,

    pub(crate) detached_signature_A: ed25519::Signature,
}

impl SendingClientAuthenticate {
    pub(crate) fn new(state: AwaitingServerHello, server_ephemeral_pk: kx::PublicKey) -> Self {
        let shared_secret_ab = state.derive_shared_secret_ab(&server_ephemeral_pk).unwrap();

        let shared_secret_aB = state.derive_shared_secret_aB().unwrap();

        let detached_signature_A = state.create_detached_signature_A(&shared_secret_ab);

        Self {
            network_identifier: state.network_identifier,

            client_longterm_pk: state.client_longterm_pk,
            client_longterm_sk: state.client_longterm_sk,
            server_longterm_pk: state.server_longterm_pk,

            client_ephemeral_pk: state.client_ephemeral_pk,
            //client_ephemeral_sk: state.client_ephemeral_sk,
            server_ephemeral_pk,

            shared_secret_ab,
            shared_secret_aB,

            detached_signature_A,
        }
    }

    fn compute_shared_secret_Ab(&self) -> Result<GroupElement, HandshakeError> {
        let client_longterm_sk = ed25519::to_curve25519_sk(&self.client_longterm_sk)
            .map_err(|_| HandshakeError::Ed25519ToCurve25519ConverstionFailed)?;
        let client_longterm_sk = Scalar(client_longterm_sk.0);

        let server_ephemeral_pk = GroupElement::from_slice(self.server_ephemeral_pk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        scalarmult(&client_longterm_sk, &server_ephemeral_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }
}

pub struct AwaitingServerAccept {
    pub(crate) network_identifier: auth::Key,

    pub(crate) client_longterm_pk: ed25519::PublicKey,
    //pub(crate) client_longterm_sk: ed25519::SecretKey,
    pub(crate) server_longterm_pk: ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    //pub(crate) client_ephemeral_sk: kx::SecretKey,
    pub(crate) server_ephemeral_pk: kx::PublicKey,

    pub(crate) shared_secret_ab: GroupElement,
    pub(crate) shared_secret_aB: GroupElement,
    pub(crate) shared_secret_Ab: GroupElement,

    pub(crate) detached_signature_A: ed25519::Signature,
}

impl AwaitingServerAccept {
    fn new(state: SendingClientAuthenticate) -> Self {
        let shared_secret_Ab = state.compute_shared_secret_Ab().unwrap();

        Self {
            network_identifier: state.network_identifier,

            client_longterm_pk: state.client_longterm_pk,
            //client_longterm_sk: state.client_longterm_sk,
            server_longterm_pk: state.server_longterm_pk,

            client_ephemeral_pk: state.client_ephemeral_pk,
            //client_ephemeral_sk: state.client_ephemeral_sk,
            server_ephemeral_pk: state.server_ephemeral_pk,

            shared_secret_ab: state.shared_secret_ab,
            shared_secret_aB: state.shared_secret_aB,
            shared_secret_Ab,

            detached_signature_A: state.detached_signature_A,
        }
    }

    fn decrypt_detached_signature_B(
        &self,
        server_accept_message: [u8; SHS_SERVER_ACCEPT_MESSAGE_LEN],
    ) -> Result<ed25519::Signature, HandshakeError> {
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let key = secretbox::Key(
            sha256::hash(
                &[
                    self.network_identifier.as_ref(),
                    self.shared_secret_ab.as_ref(),
                    self.shared_secret_aB.as_ref(),
                    self.shared_secret_Ab.as_ref(),
                ]
                .concat(),
            )
            .0,
        );
        let plaintext = secretbox::open(&server_accept_message, &nonce, &key)
            .map_err(|_| HandshakeError::ServerAcceptDecryptionFailed)?;

        ed25519::Signature::from_bytes(&plaintext).map_err(|e| {
            log::warn!("Received error when trying to reconstruct detached signature B: {e}");
            HandshakeError::ServerAcceptVerificationFailed
        })
    }

    fn compute_secret_box_keys(&self) -> (secretbox::Key, secretbox::Key) {
        let secretbox_key_inner = sha256::hash(
            sha256::hash(
                &[
                    self.network_identifier.as_ref(),
                    self.shared_secret_ab.as_ref(),
                    self.shared_secret_aB.as_ref(),
                    self.shared_secret_Ab.as_ref(),
                ]
                .concat(),
            )
            .as_ref(),
        );

        let sending_key = secretbox::Key(
            sha256::hash(
                &[
                    secretbox_key_inner.as_ref(),
                    self.server_longterm_pk.as_ref(),
                ]
                .concat(),
            )
            .0,
        );

        let receiving_key = secretbox::Key(
            sha256::hash(
                &[
                    secretbox_key_inner.as_ref(),
                    self.client_longterm_pk.as_ref(),
                ]
                .concat(),
            )
            .0,
        );

        (sending_key, receiving_key)
    }

    fn compute_sending_nonce(&self) -> Result<secretbox::Nonce, HandshakeError> {
        let sending_nonce = secretbox::Nonce(
            auth::authenticate(self.server_ephemeral_pk.as_ref(), &self.network_identifier).0
                [0..secretbox::NONCEBYTES]
                .try_into()
                .map_err(|_v| {
                    log::error!("Error creating nonce due to invalid length, should not happen");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );

        Ok(sending_nonce)
    }

    fn compute_receiving_nonce(&self) -> Result<secretbox::Nonce, HandshakeError> {
        let receiving_nonce = secretbox::Nonce(
            auth::authenticate(self.client_ephemeral_pk.as_ref(), &self.network_identifier).0
                [0..secretbox::NONCEBYTES]
                .try_into()
                .map_err(|_v| {
                    log::error!("Error creating nonce due to invalid length, should not happen");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );
        Ok(receiving_nonce)
    }
}

impl<C: Read + Write> Handshake<SendingClientHello, C> {
    pub fn new(
        channel: C,

        network_identifier: auth::Key,

        client_longterm_pk: ed25519::PublicKey,
        client_longterm_sk: ed25519::SecretKey,
        server_longterm_pk: ed25519::PublicKey,

        client_ephemeral_pk: kx::PublicKey,
        client_ephemeral_sk: kx::SecretKey,
    ) -> Self {
        Handshake {
            state: SendingClientHello {
                network_identifier,

                client_longterm_pk,
                client_longterm_sk,
                server_longterm_pk,

                client_ephemeral_pk,
                client_ephemeral_sk,
            },
            channel,
        }
    }

    pub fn send_client_hello(
        mut self,
    ) -> Result<Handshake<AwaitingServerHello, C>, HandshakeError> {
        let network_hmac = auth::authenticate(
            self.state.client_ephemeral_pk.as_ref(),
            &self.state.network_identifier,
        );

        log::trace!(
            "client_ephemeral_pk: {:?}",
            self.state.client_ephemeral_pk.hex_dump()
        );
        log::trace!(
            "client network hmac: {:?}",
            self.state.network_identifier.hex_dump()
        );

        if cfg!(feature = "vectored") {
            unimplemented!()
        } else {
            let client_hello = [
                network_hmac.as_ref(),
                self.state.client_ephemeral_pk.as_ref(),
            ]
            .concat();

            log::debug!("request: client hello: {:?}", client_hello.hex_dump());
            self.channel
                .write_all(&client_hello)
                .map_err(HandshakeError::from)?;

            Ok(Handshake {
                state: AwaitingServerHello::from(self.state),
                channel: self.channel,
            })
        }
    }
}

impl<C: Read + Write> Handshake<AwaitingServerHello, C> {
    pub fn read_server_hello(&mut self) -> Result<(auth::Tag, kx::PublicKey), HandshakeError> {
        let mut read_buff = [0; SHS_SERVER_HELLO_MESSAGE_LEN];
        self.channel
            .read_exact(&mut read_buff)
            .map_err(|e| {
                match e.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        log::error!("connection has been terminated; this can indicate invalid longterm server keys, tampering, or interrupted connection");
                        HandshakeError::ConnectionInterrupted(e)
                    }
                    _ => HandshakeError::from(e)
                }
            })?;

        log::trace!("received: server hello: {:?}", read_buff.hex_dump());

        // we could use nightly split_array to get owned array here
        let (server_hmac, server_ephemeral_pk) = read_buff.split_at(auth::TAGBYTES);

        let server_hmac =
            auth::Tag::from_slice(server_hmac).ok_or(HandshakeError::SodiumoxideInvalidLength)?;
        let server_ephemeral_pk = kx::PublicKey::from_slice(server_ephemeral_pk)
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        Ok((server_hmac, server_ephemeral_pk))
    }

    pub fn handle_server_hello(
        mut self,
    ) -> Result<Handshake<SendingClientAuthenticate, C>, HandshakeError> {
        let (server_hmac, server_ephemeral_pk) = self.read_server_hello()?;

        if !auth::verify(
            &server_hmac,
            server_ephemeral_pk.as_ref(),
            &self.state.network_identifier,
        ) {
            Err(HandshakeError::ServerHelloVerificationFailed)
        } else {
            Ok(Handshake {
                state: SendingClientAuthenticate::new(self.state, server_ephemeral_pk),
                channel: self.channel,
            })
        }
    }
}

impl<C: Read + Write> Handshake<SendingClientAuthenticate, C> {
    pub fn send_client_authenticate(
        mut self,
    ) -> Result<Handshake<AwaitingServerAccept, C>, HandshakeError> {
        let msg = [
            self.state.detached_signature_A.as_ref(),
            self.state.client_longterm_pk.as_ref(),
        ]
        .concat();
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let key = secretbox::Key(
            sha256::hash(
                &[
                    self.state.network_identifier.as_ref(),
                    self.state.shared_secret_ab.as_ref(),
                    self.state.shared_secret_aB.as_ref(),
                ]
                .concat(),
            )
            .0,
        );

        let client_authenticate_message: [u8; SHS_CLIENT_AUTHENTICATE_MESSAGE_LEN] =
            secretbox::seal(&msg, &nonce, &key)
                .try_into()
                .map_err(|v: Vec<u8>| {
                    log::error!("encrypted message has invalid length");
                    log::trace!("prepared authenticate message: {:?}", v.hex_dump());
                    HandshakeError::SodiumoxideInvalidLength
                })?;

        log::debug!(
            "request: client authenticate: {:?}",
            client_authenticate_message.hex_dump()
        );

        self.channel
            .write_all(&client_authenticate_message)
            .map_err(HandshakeError::IoError)?;

        Ok(Handshake {
            state: AwaitingServerAccept::new(self.state),
            channel: self.channel,
        })
    }
}

impl<C: Read + Write> Handshake<AwaitingServerAccept, C> {
    pub fn verify_server_accept(mut self) -> Result<PeerConnection<C>, HandshakeError> {
        let mut ciphertext_buffer = [0; SHS_SERVER_ACCEPT_MESSAGE_LEN];
        self.channel
            .read_exact(&mut ciphertext_buffer)
            .map_err(|e| {
                match e.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        log::error!("connection has been terminated; this can indicate invalid longterm server keys, tampering, or interrupted connection");
                        HandshakeError::ConnectionInterrupted(e)
                    }
                    _ => HandshakeError::from(e)
                }
            })?;

        log::trace!(
            "received: server accept: {:?}",
            ciphertext_buffer.hex_dump()
        );

        let detached_signature_B = self.state.decrypt_detached_signature_B(ciphertext_buffer)?;

        let msg = [
            self.state.network_identifier.as_ref(),
            self.state.detached_signature_A.as_ref(),
            self.state.client_longterm_pk.as_ref(),
            sha256::hash(self.state.shared_secret_ab.as_ref()).as_ref(),
        ]
        .concat();

        let (sending_key, receiving_key) = self.state.compute_secret_box_keys();

        let sending_nonce = self.state.compute_sending_nonce()?;
        let receiving_nonce = self.state.compute_receiving_nonce()?;

        if ed25519::verify_detached(&detached_signature_B, &msg, &self.state.server_longterm_pk) {
            Ok(PeerConnection::new(
                self.channel,
                sending_key,
                sending_nonce,
                receiving_key,
                receiving_nonce,
            ))
        } else {
            Err(HandshakeError::ServerAcceptVerificationFailed)
        }
    }
}
