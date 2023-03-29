use sodiumoxide::crypto::secretbox;
use std::io::{self, Read, Write};

pub struct PeerConnection<C: Read + Write> {
    channel: C,

    sending_key: secretbox::Key,
    sending_nonce: secretbox::Nonce,

    _receiving_key: secretbox::Key,
    _receiving_nonce: secretbox::Nonce,
}

impl<C: Read + Write> PeerConnection<C> {
    pub fn new(
        channel: C,
        sending_key: secretbox::Key,
        sending_nonce: secretbox::Nonce,
        receiving_key: secretbox::Key,
        receiving_nonce: secretbox::Nonce,
    ) -> Self {
        Self {
            channel,
            sending_key,
            sending_nonce,
            _receiving_key: receiving_key,
            _receiving_nonce: receiving_nonce,
        }
    }

    pub fn goodbye(mut self) -> Result<(), io::Error> {
        let goodbye_header_body = [0; 18];

        let goodbye_message =
            secretbox::seal(&goodbye_header_body, &self.sending_nonce, &self.sending_key);

        self.channel.write_all(&goodbye_message)?;
        self.channel.flush()
    }
}
