use std::io::{Error, ErrorKind};

use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::Packet;
use crate::protocol::types::ClientCommand;

/// Структура приветствия клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
  pub command: ClientCommand,
  pub target_host: Option<String>,
}

impl Packet for CommandRequest {
  async fn decode(payload: &mut bytes::Bytes) -> std::io::Result<Self> {
    let command = ClientCommand::from_byte(payload.try_get_u8()?).ok_or(Error::new(ErrorKind::InvalidData, "invalid client command"))?;

    let target_host = {
      if command == ClientCommand::Proxy {
        let host_len = payload.try_get_u8()? as usize;
        let host_bytes = payload.slice(..host_len);
        Some(String::from_utf8_lossy(&host_bytes).to_string())
      } else {
        None
      }
    };

    Ok(Self { command, target_host })
  }

  async fn encode(&self) -> bytes::Bytes {
    let mut payload = BytesMut::with_capacity(1 + if let Some(host) = &self.target_host { 1 + host.len() } else { 0 });
    payload.put_u8(self.command.to_byte());

    if let Some(host) = &self.target_host {
      payload.put_u8(host.len() as u8);
      payload.put_slice(host.as_bytes());
    }

    payload.freeze()
  }
}
