use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::RwLock;

use crate::protocol::{CryptoSession, Packet};

/// Метод чтения данных
pub async fn read_payload<R>(r: &mut R) -> std::io::Result<Bytes>
where
  R: AsyncRead + Unpin + Send,
{
  // Фрагментированная длина данных (минимум 0 бит, максимум 4294967295 бит)
  let mut fragmented_length = [0u8; 4];
  r.read_exact(&mut fragmented_length).await?;

  // Итоговая длина данных
  let length = u32::from_be_bytes(fragmented_length) as usize;

  // Данные без учёта длины
  let mut payload = vec![0u8; length];
  r.read_exact(&mut payload).await?;

  Ok(Bytes::from(payload))
}

/// Метод чтения зашифрованных данных
pub async fn read_encrypted_payload<R>(r: &mut R, crypto_session: &CryptoSession) -> std::io::Result<Bytes>
where
  R: AsyncRead + Unpin + Send,
{
  // Фрагментированная длина данных (минимум 0 бит, максимум 4294967295 бит)
  let mut fragmented_length = [0u8; 4];
  r.read_exact(&mut fragmented_length).await?;

  // Итоговая длина зашифрованных данных
  let length = u32::from_be_bytes(fragmented_length) as usize;

  // Зашифрованные данные без учёта длины
  let mut payload = vec![0u8; length];
  r.read_exact(&mut payload).await?;

  // Расшифровка данных
  let decrypted = crypto_session.decrypt(&payload)?;

  Ok(Bytes::from(decrypted))
}

/// Метод чтения пакета
pub async fn read_packet<R, T>(r: &mut R) -> std::io::Result<T>
where
  R: AsyncRead + Unpin + Send,
  T: Packet,
{
  let mut payload = read_payload(r).await?;
  T::decode(&mut payload).await
}

/// Метод чтения зашифрованного пакета
pub async fn read_encrypted_packet<R, T>(r: &mut R, crypto_session: &CryptoSession) -> std::io::Result<T>
where
  R: AsyncRead + Unpin + Send,
  T: Packet,
{
  let mut payload = read_encrypted_payload(r, crypto_session).await?;
  T::decode(&mut payload).await
}

/// Метод чтения данных из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_payload_rw(half: &Arc<RwLock<OwnedReadHalf>>) -> std::io::Result<Bytes> {
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  read_payload(&mut *half_guard).await
}

/// Метод чтения пакета из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_packet_rw<T>(half: &Arc<RwLock<OwnedReadHalf>>) -> std::io::Result<T>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let mut payload = read_payload(&mut *half_guard).await?;
  T::decode(&mut payload).await
}

/// Метод чтения зашифрованного пакета из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_encrypted_packet_rw<T>(half: &Arc<RwLock<OwnedReadHalf>>, crypto_session: &CryptoSession) -> std::io::Result<T>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let mut payload = read_encrypted_payload(&mut *half_guard, crypto_session).await?;
  T::decode(&mut payload).await
}
