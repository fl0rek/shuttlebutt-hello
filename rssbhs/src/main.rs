use clap::{Parser, Subcommand};
use rssbhs::{handshake::Handshake, PeerInfo, SetupError};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{auth, kx, sign};
use std::{
    env, fs,
    io::{self, Write},
    net::TcpStream,
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

    let main_network_identifier =
        get_network_identifier(&args.network).expect("Unable to get network identifier");

    let peer = match args.subcommand {
        Mode::Discovery { port } => {
            rssbhs::discovery::discover_local_peer(port).expect("Error during peer discovery")
        }
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
