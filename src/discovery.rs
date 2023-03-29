use crate::{PeerInfo, SetupError};
use bytes::Bytes;
use std::net::{SocketAddr, UdpSocket};

const DISCOVERY_MESSAGE_BUFFER_LEN: usize = 512;

/// listen on UDP port for local SSB servers and return _first_ match
pub fn discover_local_peer(port: u16) -> Result<PeerInfo, SetupError> {
    // we're using socket2 here, so that we can set SO_REUSEADDR
    // this is helpful in case where some other ssb node also wants to listen for local discovery
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let bind_address: SocketAddr = format!("0.0.0.0:{port}").parse().map_err(|e| {
        log::warn!("Cannot prepare addr to bind to for local discovery: {e}");
        SetupError::ErrorListeningForDiscoveryMessage
    })?;
    socket.set_reuse_address(true)?;
    socket.bind(&bind_address.into())?;
    let socket: UdpSocket = socket.into();

    // while reading to a half-kb byte buffer should handle most real-world situations
    // real world implementation shuld consider dynamically resising the window (with reasonable
    // upper limit)
    let mut read_buffer = [0; DISCOVERY_MESSAGE_BUFFER_LEN];

    loop {
        let (count, src) = socket
            .recv_from(read_buffer.as_mut())
            .map_err(SetupError::IoError)?;
        log::trace!("received {count} bytes from {src}");

        if count == DISCOVERY_MESSAGE_BUFFER_LEN {
            log::warn!("received possibly truncated message")
        }

        // we split message with bytes crate, because truncating it may break utf8
        // this way, only the last address will be affected
        let discovery_bytes = Bytes::copy_from_slice(&read_buffer[0..count]);
        for address_bytes in discovery_bytes.split(|b| *b == b';') {
            let address = String::from_utf8(address_bytes.to_vec()).map_err(|e| {
                log::warn!("Failed to utf8 parse received SSB address: {e}");
                SetupError::ErrorParsingDiscoveryMessage
            })?;
            log::info!("received address from discovery message: {address}");

            match address.parse() {
                Ok(peer_info) => return Ok(peer_info),
                Err(_) => {
                    continue;
                }
            }
        }
    }
}
