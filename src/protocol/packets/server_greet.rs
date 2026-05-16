use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::Packet;

/// Структура приветствия клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGreet {
  pub version: u16,
  pub require_auth: bool,
}

impl Packet for ServerGreet {
  async fn decode(payload: &mut bytes::Bytes) -> std::io::Result<Self> {
    Ok(Self {
      version: payload.try_get_u16()?,
      require_auth: payload.try_get_u8()? == 0x01,
    })
  }

  async fn encode(&self) -> bytes::Bytes {
    let mut payload = BytesMut::with_capacity(3);
    payload.put_u16(self.version);
    payload.put_u8(if self.require_auth { 0x01 } else { 0x00 });
    payload.freeze()
  }
}
