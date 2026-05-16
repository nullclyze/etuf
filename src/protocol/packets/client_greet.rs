use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::Packet;

/// Структура приветствия клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGreet {
  pub version: u16,
}

impl Packet for ClientGreet {
  async fn decode(bytes: &mut bytes::Bytes) -> std::io::Result<Self> {
    Ok(Self {
      version: bytes.try_get_u16()?,
    })
  }

  async fn encode(&self) -> bytes::Bytes {
    let mut data = BytesMut::with_capacity(2);
    data.put_u16(self.version);
    data.freeze()
  }
}
