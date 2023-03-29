use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use shuttlebutt_hello::{connect_to_tcp_peer, discovery, PeerInfo, SetupError};
use sodiumoxide::crypto::{auth, sign};
use std::{
    env, fs,
    io::{self, Write},
    path,
};

/// Program uses main scuttlebutt network by default
const MAIN_NETWORK_IDENTIFIER: &str =
    "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
const DEFAULT_DISCOVERY_PORT: u16 = 8008;

const CLIENT_KEY_FILE_VAR: &str = "CLIENT_KEY_FILE";
const CLIENT_KEY_FILE: &str = "client.keys";

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

fn main() -> std::io::Result<()> {
    sodiumoxide::init().expect("Failed to init sodiumoxide");
    pretty_env_logger::init_timed();

    let args = Opts::parse();

    let network_identifier = get_network_identifier(&args.network)
        .map_err(|e| {
            log::error!("Unable to decode network identifier");
            e
        })
        .expect("cannot get network identifier");

    let longterm_client_key_path = match env::var(CLIENT_KEY_FILE) {
        Ok(v) => v,
        Err(env::VarError::NotPresent) => CLIENT_KEY_FILE.to_owned(),
        Err(e) => {
            log::warn!("Could not read {CLIENT_KEY_FILE_VAR} env var: {e}, using default");
            CLIENT_KEY_FILE.to_owned()
        }
    };

    let peer = match args.subcommand {
        Mode::Discovery { port } => discovery::discover_local_peer(port),
        Mode::Manual {
            host,
            port,
            server_public_key,
        } => {
            let stripped_prefix = server_public_key
                .strip_prefix('@')
                .unwrap_or(&server_public_key);
            let stripped_key = stripped_prefix
                .strip_suffix(".ed25519")
                .unwrap_or(stripped_prefix);
            PeerInfo::try_new(stripped_key, &host, port)
        }
    }
    .map_err(|e| {
        log::error!("Received error preparing peer information: {e}");
        e
    })
    .expect("cannot gather peer info");

    log::info!("will try to connect to peer: {peer}");

    let ClientLongtermKeypair {
        public: client_longterm_pk,
        secret: client_longterm_sk,
    } = get_longterm_client_key(longterm_client_key_path)
        .expect("Failed to setup longterm client keys");

    let peer_connection = connect_to_tcp_peer(
        &peer,
        client_longterm_pk,
        client_longterm_sk,
        network_identifier,
    )
    .map_err(|e| {
        log::error!("Received error during handshake: {e}");
        e
    })
    .expect("cannot connect to peer");

    println!("Connected to peer {peer} ok");

    peer_connection
        .goodbye()
        .map_err(|e| {
            log::warn!("received error when sending goodbye message: {e}, ignoring");
        })
        .ok();

    Ok(())
}
