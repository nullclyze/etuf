use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::RwLock;

use crate::protocol::{CryptoSession, Packet};

/// Функция записи данных
pub async fn write_payload<W>(w: &mut W, payload: &[u8]) -> std::io::Result<()>
where
  W: AsyncWrite + Unpin + Send,
{
  let mut buf = BytesMut::with_capacity(4 + payload.len());
  buf.put_u32(payload.len() as u32);
  buf.put_slice(payload);

  w.write_all(&buf.freeze()).await?;
  w.flush().await
}

/// Функция записи зашифрованных данных
pub async fn write_encrypted_payload<W>(w: &mut W, payload: &[u8], crypto_session: &mut CryptoSession) -> std::io::Result<()>
where
  W: AsyncWrite + Unpin + Send,
{
  let encrypted = crypto_session.encrypt(payload)?;

  let mut buf = BytesMut::with_capacity(4 + encrypted.len());
  buf.put_u32(encrypted.len() as u32);
  buf.put_slice(&encrypted);

  w.write_all(&buf.freeze()).await?;
  w.flush().await
}

/// Функция записи пакета
pub async fn write_packet<W, T>(w: &mut W, packet: &T) -> std::io::Result<()>
where
  W: AsyncWrite + Unpin + Send,
  T: Packet,
{
  let payload = packet.encode().await;
  write_payload(w, &payload).await
}

/// Функция записи зашифрованного пакета
pub async fn write_encrypted_packet<W, T>(w: &mut W, packet: &T, crypto_session: &mut CryptoSession) -> std::io::Result<()>
where
  W: AsyncWrite + Unpin + Send,
  T: Packet,
{
  let payload = packet.encode().await;
  write_encrypted_payload(w, &payload, crypto_session).await
}

/// Функция записи данных в `Arc<RwLock<OwnedWriteHalf>>`
pub async fn write_payload_rw(half: &Arc<RwLock<OwnedWriteHalf>>, payload: &[u8]) -> std::io::Result<()> {
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  write_payload(&mut *half_guard, payload).await
}

/// Функция записи пакета в `Arc<RwLock<OwnedWriteHalf>>`
pub async fn write_packet_rw<T>(half: &Arc<RwLock<OwnedWriteHalf>>, packet: &T) -> std::io::Result<()>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let payload = packet.encode().await;
  write_payload(&mut *half_guard, &payload).await
}

/// Функция записи зашифрованных данных в `Arc<RwLock<OwnedWriteHalf>>`
pub async fn write_encrypted_payload_rw(
  half: &Arc<RwLock<OwnedWriteHalf>>,
  payload: &[u8],
  crypto_session: &Arc<RwLock<CryptoSession>>,
) -> std::io::Result<()> {
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let mut crypto_guard = tokio::time::timeout(Duration::from_secs(6), crypto_session.write()).await?;

  write_encrypted_payload(&mut *half_guard, payload, &mut crypto_guard).await
}

/// Функция записи зашифрованного пакета в `Arc<RwLock<OwnedWriteHalf>>`
pub async fn write_encrypted_packet_rw<T>(
  half: &Arc<RwLock<OwnedWriteHalf>>,
  packet: &T,
  crypto_session: &Arc<RwLock<CryptoSession>>,
) -> std::io::Result<()>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let mut crypto_guard = tokio::time::timeout(Duration::from_secs(6), crypto_session.write()).await?;

  let payload = packet.encode().await;

  write_encrypted_payload(&mut *half_guard, &payload, &mut crypto_guard).await
}
