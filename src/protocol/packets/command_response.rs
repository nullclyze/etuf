use std::io::{Error, ErrorKind};

use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::Packet;
use crate::protocol::types::CommandStatus;

/// Структура приветствия клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResponse {
  pub status: CommandStatus,
}

impl Packet for CommandResponse {
  async fn decode(payload: &mut bytes::Bytes) -> std::io::Result<Self> {
    Ok(Self {
      status: CommandStatus::from_byte(payload.try_get_u8()?).ok_or(Error::new(ErrorKind::InvalidData, "invalid command status"))?,
    })
  }

  async fn encode(&self) -> bytes::Bytes {
    let mut payload = BytesMut::with_capacity(1);
    payload.put_u8(self.status.to_byte());
    payload.freeze()
  }
}
