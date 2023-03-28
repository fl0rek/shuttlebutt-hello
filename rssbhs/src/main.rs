#![allow(non_snake_case)] // we want to match names used in ssb documentation

use openssl::sha::sha256;
use pretty_hex::*;
use sodiumoxide::crypto::auth;
//use sodiumoxide::crypto::kx::gen_keypair;
use sodiumoxide::base64;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::scalarmult::scalarmult;
use sodiumoxide::crypto::scalarmult::{GroupElement, Scalar};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign::{self, Signature};
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use thiserror::Error;

const SHS_CLIENT_AUTHENTICATE_MESSAGE_LEN: usize = 112;
const SHS_SERVER_ACCEPT_MESSAGE_LEN: usize = 80;

const MULTISERVER_ADDRESS: &str = "net:172.29.86.171:8008~shs:LDwmAY+cmuOI+VV7CK2hz78Zh78aL7er2e/lnmJib20=;ws://172.29.86.171:8989~shs:LDwmAY+cmuOI+VV7CK2hz78Zh78aL7er2e/lnmJib20=";

const IP: &str = "172.29.86.171";
const PORT: &str = "9999"; // "8008";
                           //const SHS: &str = "LDwmAY+cmuOI+VV7CK2hz78Zh78aL7er2e/lnmJib20=";
const SHS: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

const MAIN_NETWORK_IDENTIFIER: &str =
    "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";

/*
fn gen_client_ephemeral_key() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let ephemeral = PKey::generate_x25519()?;

    let raw_priv = ephemeral.raw_private_key()?;
    let raw_pub = ephemeral.raw_public_key()?;

    Ok((raw_priv, raw_pub))
}
*/

struct KeyStore {}

impl KeyStore {
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

    pub fn compute_detached_signature_B(
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

        Ok(sign::ed25519::Signature::new(
            plaintext.try_into().map_err(|v: Vec<u8>| {
                log::warn!("Decrypted server accept message has invalid length");
                log::trace!("decrypted message: {:?}", v.hex_dump());
                HandshakeError::SodiumoxideInvalidLength
            })?,
        ))
    }
}

fn get_longterm_client_key() -> (sign::ed25519::PublicKey, sign::ed25519::SecretKey) {
    // TODO: these should be permanent
    sign::gen_keypair()
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

// TODO: convert to result?
fn server_hello_verify(authenticator: &[u8; 32], msg: &[u8; 32], key: &auth::Key) -> bool {
    let tag = auth::Tag::from_slice(authenticator).expect("cannot get tag");
    auth::verify(&tag, msg, key)
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

struct Handshake<State, C: Read + Write> {
    state: State,
    channel: C,
}

struct PeerConnection<C: Read + Write> {
    channel: C,
}

pub struct SendingClientHello;
pub struct AwaitingServerHello;
pub struct DerivingSharedSecret;
pub struct SendingClientAuthenticate;
pub struct AwaitingServerAccept;

#[derive(Error, Debug)]
enum HandshakeError {
    #[error("Server hello verification failed")]
    ServerHelloVerificationFailed,

    #[error("Invalid length error from sodiumoxide, should not happen")]
    SodiumoxideInvalidLength,

    //https://docs.rs/sodiumoxide/latest/sodiumoxide/crypto/scalarmult/curve25519/fn.scalarmult.html
    #[error("Tried to scalarmult with zero GroupElement")]
    ScalarMultZeroGroupElement,

    #[error("Get invalid longterm server public key")]
    InvalidLongtermServerPublicKey,

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
    pub fn new(channel: C) -> Self {
        Handshake {
            state: SendingClientHello,
            channel,
        }
    }

    pub fn send_client_hello(
        mut self,
        client_ephemeral_pk: &kx::PublicKey,
        network_identifier: &auth::Key,
    ) -> Result<Handshake<AwaitingServerHello, C>, HandshakeError> {
        let network_hmac = auth::authenticate(client_ephemeral_pk.as_ref(), network_identifier);
        log::trace!("client_ephemeral_pk: {:?}", client_ephemeral_pk.hex_dump());
        log::trace!("client network hmac: {:?}", network_identifier.hex_dump());

        if cfg!(feature = "vectored") {
            unimplemented!()
        } else {
            let client_hello = [network_hmac.as_ref(), client_ephemeral_pk.as_ref()].concat();
            log::debug!("request: {:?}", client_hello.hex_dump());
            self.channel
                .write_all(&client_hello)
                .map_err(HandshakeError::from)?;

            Ok(Handshake {
                state: AwaitingServerHello,
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

        // we could use nightly split_array to get owned array here
        let (server_hmac, server_ephemeral_pk) = read_buff.split_at(32);

        let server_hmac =
            auth::Tag::from_slice(server_hmac).ok_or(HandshakeError::SodiumoxideInvalidLength)?;
        let server_ephemeral_pk = kx::PublicKey::from_slice(server_ephemeral_pk)
            .ok_or(HandshakeError::SodiumoxideInvalidLength)?;

        Ok((server_hmac, server_ephemeral_pk))
    }

    pub fn verify_server_hello(
        self,
        server_hmac: &auth::Tag,
        server_ephemeral_pk: &kx::PublicKey,
        network_identifier: &auth::Key,
    ) -> Result<Handshake<SendingClientAuthenticate, C>, HandshakeError> {
        if !auth::verify(
            server_hmac,
            server_ephemeral_pk.as_ref(),
            network_identifier,
        ) {
            Err(HandshakeError::ServerHelloVerificationFailed)
        } else {
            Ok(Handshake {
                state: SendingClientAuthenticate,
                channel: self.channel,
            })
        }
    }
}

impl<C: Read + Write> Handshake<SendingClientAuthenticate, C> {
    pub fn send_client_authenticate(
        mut self,
        detached_signature_A: &sign::Signature,
        client_longterm_pk: &sign::PublicKey,
        network_identifier: &auth::Key,
        shared_secret_ab: &GroupElement,
        shared_secret_aB: &GroupElement,
    ) -> Result<Handshake<AwaitingServerAccept, C>, HandshakeError> {
        let msg = [detached_signature_A.as_ref(), client_longterm_pk.as_ref()].concat();
        let nonce = secretbox::Nonce([0; 24]);
        let key = secretbox::Key(
            sha256::hash(
                &[
                    network_identifier.as_ref(),
                    shared_secret_ab.as_ref(),
                    shared_secret_aB.as_ref(),
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
            state: AwaitingServerAccept,
            channel: self.channel,
        })
    }
}

impl<C: Read + Write> Handshake<AwaitingServerAccept, C> {
    pub fn verify_server_accept(
        mut self,
        network_identifier: &auth::Key,
        shared_secret_ab: &GroupElement,
        shared_secret_aB: &GroupElement,
        shared_secret_Ab: &GroupElement,

        detached_signature_A: &sign::ed25519::Signature,
        client_longterm_pk: &sign::ed25519::PublicKey,
        server_longterm_pk: &sign::ed25519::PublicKey,
    ) -> Result<PeerConnection<C>, HandshakeError> {
        let mut ciphertext_buffer = [0; SHS_SERVER_ACCEPT_MESSAGE_LEN];
        self.channel
            .read_exact(&mut ciphertext_buffer)
            .map_err(HandshakeError::IoError)?;

        let detached_signature_B = KeyStore::compute_detached_signature_B(
            ciphertext_buffer,
            network_identifier,
            shared_secret_ab,
            shared_secret_aB,
            shared_secret_Ab,
        )?;

        let msg = [
            network_identifier.as_ref(),
            detached_signature_A.as_ref(),
            client_longterm_pk.as_ref(),
            sha256::hash(shared_secret_ab.as_ref()).as_ref(),
        ]
        .concat();

        if sign::ed25519::verify_detached(&detached_signature_B, &msg, server_longterm_pk) {
            Ok(PeerConnection {
                channel: self.channel,
            })
        } else {
            Err(HandshakeError::ServerAcceptVerificationFailed)
        }
    }
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

// TODO: less hardcoding
fn get_server_longterm_pk() -> Result<sign::ed25519::PublicKey, HandshakeError> {
    let server_longterm_pk: [u8; 32] = base64::decode(SHS, base64::Variant::Original)
        .map_err(|e| HandshakeError::InvalidLongtermServerPublicKey)?
        .try_into()
        .map_err(|e| {
            log::warn!("invalid len: {e:?}");
            HandshakeError::SodiumoxideInvalidLength
        })?;
    Ok(sign::ed25519::PublicKey(server_longterm_pk))
}

/*
mod premorse {
    // TODO: test message before sending
    pub fn client_hello_verify(msg: [u8; 64]) -> bool {
        unimplemented!()
    }
}
*/

fn main() -> std::io::Result<()> {
    sodiumoxide::init().expect("Failed to init sodiumoxide");
    pretty_env_logger::init_timed();

    let connaddr = format!("{IP}:{PORT}");
    let mut stream = TcpStream::connect(connaddr)?;

    let hs = Handshake::new(stream);

    let (client_ephemeral_pk, client_ephemeral_sk) = kx::gen_keypair();
    let main_network_identifier = auth::Key::from_slice(
        &hex::decode(MAIN_NETWORK_IDENTIFIER).expect("cannot unhex main ident"),
    )
    .expect("net identifier slice to key");

    let mut hs = hs
        .send_client_hello(&client_ephemeral_pk, &main_network_identifier)
        .expect("client hello err");

    let (server_hmac, server_ephemeral_pk) =
        hs.read_server_hello().expect("cannot read server hello");

    let hs = hs
        .verify_server_hello(&server_hmac, &server_ephemeral_pk, &main_network_identifier)
        .expect("cannot verify server hello");

    let server_longterm_pk = &get_server_longterm_pk().expect(" cannot get server longter pubkey"); // TODO: remove
                                                                                                    // expect
    let shared_secret_ab = derive_shared_secret_ab(&client_ephemeral_sk, &server_ephemeral_pk)
        .expect("cannot derive shared secret");
    let shared_secret_aB = derive_shared_secret_aB(&client_ephemeral_sk, &server_longterm_pk)
        .expect("cannot derive shared secret");

    let (client_longterm_pk, client_longterm_sk) = get_longterm_client_key();

    let detached_signature_A = KeyStore::create_detached_signature_A(
        &main_network_identifier,
        &server_longterm_pk,
        &shared_secret_ab,
        &client_longterm_sk,
    );

    let mut hs = hs
        .send_client_authenticate(
            &detached_signature_A,
            &client_longterm_pk,
            &main_network_identifier,
            &shared_secret_ab,
            &shared_secret_aB,
        )
        .expect("client authenticate err");

    let shared_secret_Ab =
        KeyStore::compute_shared_secret_Ab(&client_longterm_sk, &server_ephemeral_pk)
            .expect("Failed to compute shared secret Ab");

    let peer_connection = hs
        .verify_server_accept(
            &main_network_identifier,
            &shared_secret_ab,
            &shared_secret_aB,
            &shared_secret_Ab,
            &detached_signature_A,
            &client_longterm_pk,
            &server_longterm_pk,
        )
        .expect("server accept failed");

    log::info!("ok ok ok");

    Ok(())
}

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
