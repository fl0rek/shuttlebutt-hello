use sodiumoxide::{
    base64,
    crypto::{
        auth, kx,
        sign::{self, ed25519},
    },
};
use std::{fmt, io, net::TcpStream, str::FromStr};
use thiserror::Error;

pub mod connection;
pub mod discovery;
pub mod handshake;

pub fn connect_to_tcp_peer(
    peer: &PeerInfo,
    client_pk: ed25519::PublicKey,
    client_sk: ed25519::SecretKey,
    network_identifier: auth::Key,
) -> Result<connection::PeerConnection<TcpStream>, handshake::HandshakeError> {
    let stream = TcpStream::connect(&peer.connect_addr)?;

    let (client_ephemeral_pk, client_ephemeral_sk) = kx::gen_keypair();

    let client_hello = handshake::Handshake::new(
        stream,
        network_identifier,
        client_pk,
        client_sk,
        peer.server_longterm_pk,
        client_ephemeral_pk,
        client_ephemeral_sk,
    );

    let server_hello = client_hello.send_client_hello()?;
    log::info!("sent client hello");

    let client_authenticate = server_hello.handle_server_hello()?;
    log::info!("received and verified server hello");

    let server_accept = client_authenticate.send_client_authenticate()?;
    log::info!("sent client authenticate");

    let peer_connection = server_accept.verify_server_accept()?;
    log::info!("received and verified server accept");

    Ok(peer_connection)
}

#[derive(Error, Debug)]
pub enum SetupError {
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

    #[error("IO error {0}")]
    IoError(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("Address string doesn't contain required recognised protocols (net & shs)")]
    UnrecognisedProtocol,

    #[error("Failed to decode discovered peer public key")]
    InvalidPeerPublicKey,
}

#[derive(Debug)]
pub struct PeerInfo {
    pub connect_addr: String,
    pub server_longterm_pk: sign::ed25519::PublicKey,
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: convert server_longterm_pk back to base64, for proper multiserver address
        write!(f, "net:{}~shs:****", self.connect_addr)
    }
}

impl FromStr for PeerInfo {
    type Err = DiscoveryError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        let mut net = None;
        let mut shs = None;

        for protocol in address.split('~') {
            if let Some(suffix) = protocol.strip_prefix("net:") {
                net = Some(suffix);
            }
            if let Some(suffix) = protocol.strip_prefix("shs:") {
                shs = Some(suffix);
            }
        }

        match (net, shs) {
            (Some(net), Some(shs)) => Ok(PeerInfo {
                connect_addr: net.to_string(),
                server_longterm_pk: PeerInfo::decode_longterm_public_key(shs)
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
    pub fn try_new(server_pubkey: &str, host: &str, port: u16) -> Result<Self, SetupError> {
        Ok(PeerInfo {
            connect_addr: format!("{host}:{port}"),
            server_longterm_pk: PeerInfo::decode_longterm_public_key(server_pubkey)
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
