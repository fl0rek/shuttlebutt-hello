#![allow(non_snake_case)] // we want to match names used in ssb documentation

use clap::{Parser, Subcommand};
use pretty_hex::*;
use serde::{Deserialize, Serialize};
use sodiumoxide::base64;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::scalarmult::scalarmult;
use sodiumoxide::crypto::scalarmult::{GroupElement, Scalar};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::{env, fs, path};
use thiserror::Error;

const SHS_CLIENT_AUTHENTICATE_MESSAGE_LEN: usize = 112;
const SHS_SERVER_ACCEPT_MESSAGE_LEN: usize = 80;

/// Program uses main scuttlebutt network by default
const MAIN_NETWORK_IDENTIFIER: &str =
    "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
const DEFAULT_DISCOVERY_PORT: u16 = 8008;

const CLIENT_KEY_FILE_VAR: &str = "CLIENT_KEY_FILE";
const CLIENT_KEY_FILE: &str = "client.keys";

/*
struct KeyStore {}

impl KeyStore {
    /*
    pub fn compute_shared_secret_Ab(
        client_longterm_sk: &sign::ed25519::SecretKey,
        server_ephemeral_pk: &kx::PublicKey,
    ) -> Result<GroupElement, HandshakeError> {
        let client_longterm_sk = sign::ed25519::to_curve25519_sk(client_longterm_sk)
            .map_err(|_| HandshakeError::Ed25519ToCurve25519ConverstionFailed)?;
        let client_longterm_sk = Scalar(client_longterm_sk.0);

        let server_ephemeral_pk = GroupElement::from_slice(server_ephemeral_pk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        scalarmult(&client_longterm_sk, &server_ephemeral_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }
    */

    /*
    pub fn create_detached_signature_A(
        network_identifier: &auth::Key,
        server_longterm_pk: &sign::PublicKey,
        shared_secret_ab: &GroupElement,
        client_longterm_sk: &sign::SecretKey,
    ) -> sign::Signature {
        let signature_message = [
            network_identifier.as_ref(),
            server_longterm_pk.as_ref(),
            sha256::hash(shared_secret_ab.as_ref()).as_ref(),
        ]
        .concat();

        sign::sign_detached(&signature_message, client_longterm_sk)
    }
    */

    /*
    pub fn decrypt_detached_signature_B(
        server_accept_message: [u8; SHS_SERVER_ACCEPT_MESSAGE_LEN],
        network_identifier: &auth::Key,
        shared_secret_ab: &GroupElement,
        shared_secret_aB: &GroupElement,
        shared_secret_Ab: &GroupElement,
    ) -> Result<sign::ed25519::Signature, HandshakeError> {
        let nonce = secretbox::Nonce([0; 24]);
        let key = secretbox::Key(
            sha256::hash(
                &[
                    network_identifier.as_ref(),
                    shared_secret_ab.as_ref(),
                    shared_secret_aB.as_ref(),
                    shared_secret_Ab.as_ref(),
                ]
                .concat(),
            )
            .0,
        );
        let plaintext = secretbox::open(&server_accept_message, &nonce, &key)
            .map_err(|_| HandshakeError::ServerAcceptDecryptionFailed)?;

        sign::ed25519::Signature::from_bytes(&plaintext).map_err(|e| {
            log::warn!("Received error when trying to reconstruct detached signature B: {e}");
            HandshakeError::ServerAcceptVerificationFailed
        })
    }
    */

    /*
    pub fn compute_secret_box_keys(
        network_identifier: &auth::Key,
        shared_secret_ab: &GroupElement,
        shared_secret_aB: &GroupElement,
        shared_secret_Ab: &GroupElement,
        server_longterm_pk: &sign::ed25519::PublicKey,
        client_longterm_pk: &sign::ed25519::PublicKey,
    ) -> (secretbox::Key, secretbox::Key) {
        let secretbox_key_inner = sha256::hash(
            sha256::hash(
                &[
                    network_identifier.as_ref(),
                    shared_secret_ab.as_ref(),
                    shared_secret_aB.as_ref(),
                    shared_secret_Ab.as_ref(),
                ]
                .concat(),
            )
            .as_ref(),
        );

        let sending_key = secretbox::Key(
            sha256::hash(&[secretbox_key_inner.as_ref(), server_longterm_pk.as_ref()].concat()).0,
        );

        let receiving_key = secretbox::Key(
            sha256::hash(&[secretbox_key_inner.as_ref(), client_longterm_pk.as_ref()].concat()).0,
        );

        (sending_key, receiving_key)
    }
    */

    /*
    pub fn compute_starting_nonces(
        network_identifier: &auth::Key,
        client_ephemeral_pk: &kx::PublicKey,
        server_ephemeral_pk: &kx::PublicKey,
    ) -> Result<(secretbox::Nonce, secretbox::Nonce), HandshakeError> {
        let sending_nonce = secretbox::Nonce(
            auth::authenticate(server_ephemeral_pk.as_ref(), &network_identifier).0[0..24]
                .try_into()
                .map_err(|_v| {
                    log::warn!("Failed to compute initial nonce");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );

        let receiving_nonce = secretbox::Nonce(
            auth::authenticate(client_ephemeral_pk.as_ref(), &network_identifier).0[0..24]
                .try_into()
                .map_err(|_v| {
                    log::warn!("Failed to compute initial nonce");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );

        Ok((sending_nonce, receiving_nonce))
    }
    */

    /*
    fn derive_shared_secret_aB(
        client_ephemeral_sk: &kx::SecretKey,
        server_longterm_pk: &sign::ed25519::PublicKey, // longterm keys are ed25519!
    ) -> Result<GroupElement, HandshakeError> {
        let client_ephemeral_sk = Scalar::from_slice(client_ephemeral_sk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        // need to convert from ed25519 to curve25519
        let server_longterm_pk = sign::ed25519::to_curve25519_pk(server_longterm_pk)
            .map_err(|_| HandshakeError::Ed25519ToCurve25519ConverstionFailed)?;
        let server_longterm_pk = GroupElement(server_longterm_pk.0);

        scalarmult(&client_ephemeral_sk, &server_longterm_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }

    fn derive_shared_secret_ab(
        client_ephemeral_sk: &kx::SecretKey,
        server_ephemeral_pk: &kx::PublicKey,
    ) -> Result<GroupElement, HandshakeError> {
        let client_ephemeral_sk = Scalar::from_slice(client_ephemeral_sk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;
        let server_ephemeral_pk = GroupElement::from_slice(server_ephemeral_pk.as_ref())
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        scalarmult(&client_ephemeral_sk, &server_ephemeral_pk)
            .map_err(|_| HandshakeError::ScalarMultZeroGroupElement)
    }
    */
}
*/

#[derive(Error, Debug)]
enum SetupError {
    #[error("Received invalid longterm server public key")]
    InvalidLongtermServerPublicKey,

    #[error("Received invalid network identifier")]
    InvalidNetworkIdentifier,

    #[error("Error deserialising keys")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Error listening for local discovery message")]
    ErrorListeningForDiscoveryMessage,

    #[error("Failed to parse SSB local discovery message")]
    ErrorParsingDiscoveryMessage,

    #[error("IO error")]
    IoError(#[from] io::Error),
}

#[derive(Serialize, Deserialize)]
struct ClientLongtermKeypair {
    public: sign::ed25519::PublicKey,
    secret: sign::ed25519::SecretKey,
}

fn get_longterm_client_key<P: AsRef<path::Path>>(
    key_path: P,
) -> Result<ClientLongtermKeypair, SetupError> {
    let keypair = match fs::read_to_string(key_path.as_ref()) {
        Ok(s) => serde_json::from_str(&s).map_err(SetupError::DeserializationError),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => {
                log::info!("key file not found, will generate a new keypair");
                let (public, secret) = sign::gen_keypair();
                let keypair = ClientLongtermKeypair { public, secret };

                let mut f = fs::File::create(key_path.as_ref()).map_err(|e| {
                    log::warn!(
                        "failed to create keyfile {:?}: {e}",
                        key_path.as_ref().to_str()
                    );
                    SetupError::IoError(e)
                })?;
                f.write_all(serde_json::to_string(&keypair)?.as_bytes())?;

                Ok(keypair)
            }
            _ => {
                log::error!(
                    "Unhandled error when reading longterm key file {:?}: {e}",
                    key_path.as_ref().to_str()
                );
                Err(SetupError::from(e))
            }
        },
    };

    keypair
}

struct Handshake<State, C: Read + Write> {
    state: State,
    channel: C,
}

struct PeerConnection<C: Read + Write> {
    channel: C,

    sending_key: secretbox::Key,
    sending_nonce: secretbox::Nonce,

    _receiving_key: secretbox::Key,
    _receiving_nonce: secretbox::Nonce,
}

impl<C: Read + Write> PeerConnection<C> {
    fn goodbye(mut self) -> Result<(), io::Error> {
        let goodbye_header_body = [0; 18];

        let goodbye_message =
            secretbox::seal(&goodbye_header_body, &self.sending_nonce, &self.sending_key);

        self.channel.write_all(&goodbye_message)?;
        self.channel.flush()
    }
}

pub struct SendingClientHello {
    pub(crate) network_identifier: auth::Key,

    pub(crate) client_longterm_pk: sign::ed25519::PublicKey,
    pub(crate) client_longterm_sk: sign::ed25519::SecretKey,
    pub(crate) server_longterm_pk: sign::ed25519::PublicKey,

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

    pub(crate) client_longterm_pk: sign::ed25519::PublicKey,
    pub(crate) client_longterm_sk: sign::ed25519::SecretKey,
    pub(crate) server_longterm_pk: sign::ed25519::PublicKey,

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
        let server_longterm_pk = sign::ed25519::to_curve25519_pk(&self.server_longterm_pk)
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

    pub(crate) client_longterm_pk: sign::ed25519::PublicKey,
    pub(crate) client_longterm_sk: sign::ed25519::SecretKey,
    pub(crate) server_longterm_pk: sign::ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    //pub(crate) client_ephemeral_sk: kx::SecretKey,
    pub(crate) server_ephemeral_pk: kx::PublicKey,

    pub(crate) shared_secret_ab: GroupElement,
    pub(crate) shared_secret_aB: GroupElement,

    pub(crate) detached_signature_A: sign::ed25519::Signature,
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
        let client_longterm_sk = sign::ed25519::to_curve25519_sk(&self.client_longterm_sk)
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

    pub(crate) client_longterm_pk: sign::ed25519::PublicKey,
    //pub(crate) client_longterm_sk: sign::ed25519::SecretKey,
    pub(crate) server_longterm_pk: sign::ed25519::PublicKey,

    pub(crate) client_ephemeral_pk: kx::PublicKey,
    //pub(crate) client_ephemeral_sk: kx::SecretKey,
    pub(crate) server_ephemeral_pk: kx::PublicKey,

    pub(crate) shared_secret_ab: GroupElement,
    pub(crate) shared_secret_aB: GroupElement,
    pub(crate) shared_secret_Ab: GroupElement,

    pub(crate) detached_signature_A: sign::ed25519::Signature,
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
    ) -> Result<sign::ed25519::Signature, HandshakeError> {
        let nonce = secretbox::Nonce([0; 24]);
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

        sign::ed25519::Signature::from_bytes(&plaintext).map_err(|e| {
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
                [0..24]
                .try_into()
                .map_err(|_v| {
                    log::warn!("Failed to compute initial nonce");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );

        Ok(sending_nonce)
    }

    fn compute_receiving_nonce(&self) -> Result<secretbox::Nonce, HandshakeError> {
        let receiving_nonce = secretbox::Nonce(
            auth::authenticate(self.client_ephemeral_pk.as_ref(), &self.network_identifier).0
                [0..24]
                .try_into()
                .map_err(|_v| {
                    log::warn!("Failed to compute initial nonce");
                    HandshakeError::SodiumoxideInvalidLength
                })?,
        );
        Ok(receiving_nonce)
    }
}

#[derive(Error, Debug)]
enum HandshakeError {
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

    #[error("Io error")]
    IoError(#[from] io::Error),
}

impl<C: Read + Write> Handshake<SendingClientHello, C> {
    pub fn new(
        channel: C,

        network_identifier: auth::Key,

        client_longterm_pk: sign::ed25519::PublicKey,
        client_longterm_sk: sign::ed25519::SecretKey,
        server_longterm_pk: sign::ed25519::PublicKey,

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
        let mut read_buff = [0 as u8; 64];
        self.channel
            .read_exact(&mut read_buff)
            .map_err(HandshakeError::from)?;

        log::trace!("received: server hello: {:?}", read_buff.hex_dump());

        // we could use nightly split_array to get owned array here
        let (server_hmac, server_ephemeral_pk) = read_buff.split_at(32);

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
        let nonce = secretbox::Nonce([0; 24]);
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
                    log::warn!("invalid client authenticate length");
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
            .map_err(HandshakeError::IoError)?;

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

        if sign::ed25519::verify_detached(
            &detached_signature_B,
            &msg,
            &self.state.server_longterm_pk,
        ) {
            Ok(PeerConnection {
                channel: self.channel,
                sending_key,
                sending_nonce,
                _receiving_key: receiving_key,
                _receiving_nonce: receiving_nonce,
            })
        } else {
            Err(HandshakeError::ServerAcceptVerificationFailed)
        }
    }
}

#[derive(Error, Debug)]
enum DiscoveryError {
    #[error("Address string doesn't contain required recognised protocols (net & shs)")]
    UnrecognisedProtocol,

    #[error("Failed to decode discovered peer public key")]
    InvalidPeerPublicKey,
}

#[derive(Debug)]
struct PeerInfo {
    connect_addr: String,
    server_longterm_pk: sign::ed25519::PublicKey,
}

impl FromStr for PeerInfo {
    type Err = DiscoveryError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        let mut net = None;
        let mut shs = None;

        for protocol in address.split("~") {
            if protocol.starts_with("net:") {
                net = Some(protocol[4..].to_string());
            }
            if protocol.starts_with("shs:") {
                shs = Some(protocol[4..].to_string());
            }
        }

        match (net, shs) {
            (Some(net), Some(shs)) => Ok(PeerInfo {
                connect_addr: net,
                server_longterm_pk: PeerInfo::decode_longterm_public_key(&shs)
                    .ok_or(DiscoveryError::InvalidPeerPublicKey)?,
            }),
            (_, _) => {
                log::info!("skipping unrecognised protocols for address {address}");
                Err(DiscoveryError::UnrecognisedProtocol)
            }
        }
    }
}

impl PeerInfo {
    fn try_new(server_pubkey: &str, host: &str, port: u16) -> Result<Self, SetupError> {
        Ok(PeerInfo {
            connect_addr: format!("{host}:{port}"),
            server_longterm_pk: PeerInfo::decode_longterm_public_key(&server_pubkey)
                .ok_or(SetupError::InvalidLongtermServerPublicKey)?,
        })
    }

    fn decode_longterm_public_key(key: &str) -> Option<sign::ed25519::PublicKey> {
        let server_longterm_pk: [u8; 32] = base64::decode(key, base64::Variant::Original)
            .map_err(|_| {
                log::error!("Failed to base64 decode server longterm public key");
            })
            .ok()?
            .try_into()
            .map_err(|_| {
                log::error!("Decoded server longtime public key has invalid length");
            })
            .ok()?;

        Some(sign::ed25519::PublicKey(server_longterm_pk))
    }
}

#[derive(Parser, Debug)]
struct Opts {
    /// hex-encoded network key, in case you want to connect to private ssb network
    #[arg(long, default_value_t = MAIN_NETWORK_IDENTIFIER.to_string())]
    network: String,
    #[command(subcommand)]
    subcommand: Mode,
}

#[derive(Subcommand, Clone, Debug)]
enum Mode {
    /// Listen on udp PORT for scuttlebutt servers on local network
    Discovery {
        #[arg(default_value_t = DEFAULT_DISCOVERY_PORT)]
        port: u16,
    },
    /// Connect to specific address
    Manual {
        /// IP to connect to
        host: String,
        /// PORT to connect to
        port: u16,
        /// Server public key
        server_public_key: String,
    },
}

fn get_network_identifier(network_identifier: &str) -> Result<auth::Key, SetupError> {
    let network_identifier: [u8; 32] = hex::decode(network_identifier)
        .map_err(|e| {
            log::warn!("Failed to hex-decode provided network identifier: {e}");
            SetupError::InvalidNetworkIdentifier
        })?
        .try_into()
        .map_err(|_| {
            log::warn!("Hex-decoded network identifier has invalid length");
            SetupError::InvalidNetworkIdentifier
        })?;

    Ok(auth::Key(network_identifier))
}

/// listen on UDP port for local SSB servers and return _first_ match
fn discover_local_peer(port: u16) -> Result<PeerInfo, SetupError> {
    // we're using socket2 here, so that we can set SO_REUSEADDR
    // this is helpful in case where other ssb node also wants to listen for local discovery
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let bind_address: SocketAddr = format!("0.0.0.0:{port}").parse().map_err(|e| {
        log::warn!("Cannot prepare addr to bind to for local discovery: {e}");
        SetupError::ErrorListeningForDiscoveryMessage
    })?;
    socket.set_reuse_address(true)?;
    socket.bind(&bind_address.into())?;
    let socket: UdpSocket = socket.into();

    // TODO: 256 bytes should work in most situations, but we still don't handle truncated messages
    // correctly
    let mut read_buffer = [0; 256];

    loop {
        let (count, src) = socket
            .recv_from(&mut read_buffer)
            .map_err(SetupError::IoError)?;

        log::trace!("received {count} bytes from {src}");

        let discovery_buffer = String::from_utf8(read_buffer[0..count].to_vec()).map_err(|e| {
            log::warn!("Failed to utf8 parse received SSB discovery message: {e}");
            SetupError::ErrorParsingDiscoveryMessage
        })?;

        log::info!("received discovery message: {discovery_buffer}");

        for address in discovery_buffer.split(";") {
            match address.parse() {
                Ok(peer_info) => return Ok(peer_info),
                Err(_) => {
                    continue;
                }
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    sodiumoxide::init().expect("Failed to init sodiumoxide");
    pretty_env_logger::init_timed();

    let args = Opts::parse();

    let main_network_identifier =
        get_network_identifier(&args.network).expect("Unable to get network identifier");

    let peer = match args.subcommand {
        Mode::Discovery { port } => discover_local_peer(port).expect("Error during peer discovery"),
        Mode::Manual {
            host,
            port,
            server_public_key,
        } => {
            PeerInfo::try_new(&server_public_key, &host, port).expect("cannot construct peer info")
        }
    };

    log::info!("will try to connect to peer: {peer:?}");

    let longterm_client_key_path = match env::var(CLIENT_KEY_FILE) {
        Ok(v) => v,
        Err(env::VarError::NotPresent) => CLIENT_KEY_FILE.to_owned(),
        Err(e) => {
            log::warn!("Could not read {CLIENT_KEY_FILE_VAR} env var: {e}, using default");
            CLIENT_KEY_FILE.to_owned()
        }
    };

    let ClientLongtermKeypair {
        public: client_longterm_pk,
        secret: client_longterm_sk,
    } = get_longterm_client_key(longterm_client_key_path)
        .expect("Failed to setup longterm client keys");

    let stream = TcpStream::connect(peer.connect_addr)?;

    let (client_ephemeral_pk, client_ephemeral_sk) = kx::gen_keypair();

    let hs = Handshake::new(
        stream,
        main_network_identifier,
        client_longterm_pk,
        client_longterm_sk,
        peer.server_longterm_pk,
        client_ephemeral_pk,
        client_ephemeral_sk,
    );

    let hs = hs.send_client_hello().expect("client hello err");
    log::info!("sent client hello");

    let hs = hs.handle_server_hello().expect("server hello err ");
    log::info!("received and verified server hello");

    let hs = hs
        .send_client_authenticate()
        .expect("client authenticate err");
    log::info!("sent client authenticate");

    let peer_connection = hs.verify_server_accept().expect("server accept failed");
    log::info!("received and verified server accept ✓");

    peer_connection.goodbye().expect("cannot say goodbye");

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
fn _main() -> std::io::Result<()> {
    sodiumoxide::init().expect("Failed to init sodiumoxide");

    let main_net = hex::decode(MAIN_NETWORK_IDENTIFIER)
        .expect("whomp whomp: main network idenifier hexdecode");

    let main_network_identifier =
        auth::Key::from_slice(&main_net).expect("net identifier slice to key");

    let (client_ephemeral_pk, client_ephemeral_sk) = kx::gen_keypair();

    let client_hello = client_hello_create(&client_ephemeral_pk, &main_network_identifier);

    let connaddr = format!("{IP}:{PORT}");
    let mut stream = TcpStream::connect(connaddr)?;
    stream.write_all(&client_hello).expect("err writing hello1");

    let mut read_buff: [u8; 64] = [0; 64];
    stream.read_exact(&mut read_buff).expect("err sending");

    println!("response: {:?}", read_buff.hex_dump());

    let server_hmac = &read_buff[0..32];
    let server_ephemeral_pk = kx::PublicKey::from_slice(&read_buff[32..64])
        .expect("failed to extract server ephemeral sk");

    println!("sv hmac: {:?}", server_hmac.hex_dump());
    println!("sv eph pk: {:?}", server_ephemeral_pk.hex_dump());

    // verify server is using same network identifier
    if !server_hello_verify(
        server_hmac.try_into().expect("wrong len"),
        server_ephemeral_pk.as_ref().try_into().expect("wrong len"),
        &main_network_identifier,
    ) {
        println!("server hello verify failed");
        return Err(std::io::Error::new(ErrorKind::Other, "err"));
    }

    let client_ephemeral_sk_scalar =
        Scalar::from_slice(client_ephemeral_sk.as_ref()).expect("wrong len");
    let shared_secret_ab = scalarmult(
        &client_ephemeral_sk_scalar,
        &GroupElement::from_slice(server_ephemeral_pk.as_ref()).expect("wrong len"),
    )
    .expect("failed to compute shared secret ab");

    let ed25519_server_longterm_pk = sign::ed25519::PublicKey::from_slice(
        &base64::decode(SHS, base64::Variant::Original).expect("failed to unbase64 shs"),
    )
    .expect("wrong len");

    let curve25519_server_longterm_pk =
        sign::ed25519::to_curve25519_pk(&ed25519_server_longterm_pk)
            .expect("cannot convert server longterm publickey ed25519->curve25519");
    let groupelement_server_longterm_pk =
        GroupElement::from_slice(curve25519_server_longterm_pk.as_ref()).expect("wrong len");

    let shared_secret_aB = scalarmult(
        &client_ephemeral_sk_scalar,
        &groupelement_server_longterm_pk,
    )
    .expect("failed to compute shared secret aB");

    let (client_longterm_pk, client_longterm_sk) = get_longterm_client_key();

    let client_authenticate_message = client_authenticate_create(
        &main_network_identifier,
        &ed25519_server_longterm_pk,
        &shared_secret_ab,
        &shared_secret_aB,
        &client_longterm_sk,
        &client_longterm_pk,
    );

    println!(
        "sending client auth msg: {:?}",
        client_authenticate_message.hex_dump(),
    );
    stream
        .write_all(&client_authenticate_message)
        .expect("err writing client auth msg");

    let curve25519_client_longterm_sk = sign::ed25519::to_curve25519_sk(&client_longterm_sk)
        .expect("cannot convert client longterm sk ed25519->curve25519");
    let curve25519_client_longterm_sk_scalar =
        Scalar::from_slice(curve25519_client_longterm_sk.as_ref()).expect("cannot create scalar");
    let groupelement_server_ephemeral_pk = GroupElement::from_slice(server_ephemeral_pk.as_ref())
        .expect("cannot groupelement the server ephemeral pk");
    let shared_secret_Ab = scalarmult(
        &curve25519_client_longterm_sk_scalar,
        &groupelement_server_ephemeral_pk,
    )
    .expect("cannot compute secret Ab");

    let secretbox_key_inner = sha256::hash(
        sha256::hash(
            &[
                main_network_identifier.as_ref(),
                shared_secret_ab.as_ref(),
                shared_secret_aB.as_ref(),
                shared_secret_Ab.as_ref(),
            ]
            .concat(),
        )
        .as_ref(),
    );
    let secretbox_key = secretbox::Key::from_slice(
        sha256::hash(
            &[
                secretbox_key_inner.as_ref(),
                ed25519_server_longterm_pk.as_ref(),
            ]
            .concat(),
        )
        .as_ref(),
    )
    .expect("Cannot compute key");

    let goodbye_header_body = [0; 18];
    let mut nonce = secretbox::Nonce::from_slice(
        &auth::authenticate(server_ephemeral_pk.as_ref(), &main_network_identifier).as_ref()[0..24],
    )
    .expect("cannot compute nonce");

    let goodbye_message = secretbox::seal(&goodbye_header_body, &nonce, &secretbox_key);
    println!("Sending goodbye message: {:?}", goodbye_message.hex_dump());

    stream
        .write_all(&goodbye_message)
        .expect("cannot send goodbye");

    nonce.increment_le_inplace();

    let goodbye_message = secretbox::seal(&goodbye_header_body, &nonce, &secretbox_key);
    println!("Sending goodbye message: {:?}", goodbye_message.hex_dump());

    stream
        .write_all(&goodbye_message)
        .expect("cannot send goodbye");

    stream.flush().expect("cannot flush");

    Ok(())
}

fn client_hello_create(
    client_ephemeral_pk: &kx::PublicKey,
    network_identifier: &auth::Key,
) -> [u8; 64] {
    let client_hello_tag = auth::authenticate(client_ephemeral_pk.as_ref(), network_identifier);
    println!("my eph: {:?}", client_ephemeral_pk.hex_dump());
    println!("my hmac: {:?}", client_hello_tag.hex_dump());

    let client_hello = [client_hello_tag.as_ref(), client_ephemeral_pk.as_ref()].concat();
    println!("request: {:?}", client_hello.hex_dump());

    client_hello.try_into().expect("Wrong lenght")
}

fn client_authenticate_create(
    network_identifier: &auth::Key,
    server_longterm_pk: &sign::PublicKey,
    shared_secret_ab: &GroupElement,
    shared_secret_aB: &GroupElement,
    client_longterm_sk: &sign::SecretKey,
    client_longterm_pk: &sign::PublicKey,
) -> Vec<u8> {
    let signature_msg = [
        network_identifier.as_ref(),
        server_longterm_pk.as_ref(),
        sha256::hash(shared_secret_ab.as_ref()).as_ref(),
    ]
    .concat();
    let detached_signature = sign::sign_detached(&signature_msg, client_longterm_sk);

    let secretbox_msg = [detached_signature.as_ref(), client_longterm_pk.as_ref()].concat();
    let nonce = secretbox::Nonce::from_slice(&[0; 24]).expect("Cannot create nonce");
    let key = secretbox::Key::from_slice(
        sha256::hash(
            &[
                network_identifier.as_ref(),
                shared_secret_ab.as_ref(),
                shared_secret_aB.as_ref(),
            ]
            .concat(),
        )
        .as_ref(),
    )
    .expect("cannot derive key for client auth");

    let client_authenticate_message = secretbox::seal(&secretbox_msg, &nonce, &key);
    assert_eq!(client_authenticate_message.len(), 112);
    client_authenticate_message
}

fn server_hello_verify(authenticator: &[u8; 32], msg: &[u8; 32], key: &auth::Key) -> bool {
    let tag = auth::Tag::from_slice(authenticator).expect("cannot get tag");
    auth::verify(&tag, msg, key)
}
*/
