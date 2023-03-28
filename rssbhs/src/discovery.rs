use crate::{PeerInfo, SetupError};
use std::net::{SocketAddr, UdpSocket};

/// listen on UDP port for local SSB servers and return _first_ match
pub fn discover_local_peer(port: u16) -> Result<PeerInfo, SetupError> {
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

        for address in discovery_buffer.split(';') {
            match address.parse() {
                Ok(peer_info) => return Ok(peer_info),
                Err(_) => {
                    continue;
                }
            }
        }
    }
}
