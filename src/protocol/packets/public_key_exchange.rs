use std::io::{Error, ErrorKind};

use bytes::{BufMut, BytesMut};

use crate::protocol::Packet;

/// Структура обмена публичными ключами
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyExchange {
  pub public_key: [u8; 32],
}

impl Packet for PublicKeyExchange {
  async fn decode(payload: &mut bytes::Bytes) -> std::io::Result<Self> {
    Ok(Self {
      public_key: payload[..32]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "incorrect public key length"))?,
    })
  }

  async fn encode(&self) -> bytes::Bytes {
    let mut payload = BytesMut::with_capacity(self.public_key.len());
    payload.put_slice(&self.public_key);
    payload.freeze()
  }
}
