use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::RwLock;

use crate::protocol::{CryptoSession, Packet};

/// Максимальный размер данных (8мб)
const MAX_PAYLOAD_SIZE: u32 = 8_388_608;

/// Функция чтения данных
pub async fn read_payload<R>(r: &mut R) -> std::io::Result<Bytes>
where
  R: AsyncRead + Unpin + Send,
{
  // Фрагментированная длина данных
  let mut fragmented_length = [0u8; 4];
  r.read_exact(&mut fragmented_length).await?;

  // Итоговая длина данных
  let length = u32::from_be_bytes(fragmented_length);

  if length > MAX_PAYLOAD_SIZE {
    return Err(Error::new(ErrorKind::InvalidData, "payload too large"));
  }

  // Данные без учёта длины
  let mut payload = vec![0u8; length as usize];
  r.read_exact(&mut payload).await?;

  Ok(Bytes::from(payload))
}

/// Функция чтения зашифрованных данных
pub async fn read_encrypted_payload<R>(r: &mut R, crypto_session: &CryptoSession) -> std::io::Result<Bytes>
where
  R: AsyncRead + Unpin + Send,
{
  // Фрагментированная длина данных
  let mut fragmented_length = [0u8; 4];
  r.read_exact(&mut fragmented_length).await?;

  // Итоговая длина зашифрованных данных
  let length = u32::from_be_bytes(fragmented_length);

  if length > MAX_PAYLOAD_SIZE {
    return Err(Error::new(ErrorKind::InvalidData, "payload too large"));
  }

  // Зашифрованные данные без учёта длины
  let mut payload = vec![0u8; length as usize];
  r.read_exact(&mut payload).await?;

  // Расшифровка данных
  let decrypted = crypto_session.decrypt(&payload)?;

  Ok(Bytes::from(decrypted))
}

/// Функция чтения пакета
pub async fn read_packet<R, T>(r: &mut R) -> std::io::Result<T>
where
  R: AsyncRead + Unpin + Send,
  T: Packet,
{
  let mut payload = read_payload(r).await?;
  T::decode(&mut payload).await
}

/// Функция чтения зашифрованного пакета
pub async fn read_encrypted_packet<R, T>(r: &mut R, crypto_session: &CryptoSession) -> std::io::Result<T>
where
  R: AsyncRead + Unpin + Send,
  T: Packet,
{
  let mut payload = read_encrypted_payload(r, crypto_session).await?;
  T::decode(&mut payload).await
}

/// Функция чтения данных из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_payload_rw(half: &Arc<RwLock<OwnedReadHalf>>) -> std::io::Result<Bytes> {
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  read_payload(&mut *half_guard).await
}

/// Функция чтения пакета из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_packet_rw<T>(half: &Arc<RwLock<OwnedReadHalf>>) -> std::io::Result<T>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let mut payload = read_payload(&mut *half_guard).await?;
  T::decode(&mut payload).await
}

/// Функция чтения зашифрованных данных из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_encrypted_payload_rw(
  half: &Arc<RwLock<OwnedReadHalf>>,
  crypto_session: &Arc<RwLock<CryptoSession>>,
) -> std::io::Result<Bytes> {
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let crypto_guard = tokio::time::timeout(Duration::from_secs(6), crypto_session.read()).await?;

  read_encrypted_payload(&mut *half_guard, &crypto_guard).await
}

/// Функция чтения зашифрованного пакета из `Arc<RwLock<OwnedReadHalf>>`
pub async fn read_encrypted_packet_rw<T>(
  half: &Arc<RwLock<OwnedReadHalf>>,
  crypto_session: &Arc<RwLock<CryptoSession>>,
) -> std::io::Result<T>
where
  T: Packet,
{
  let mut half_guard = tokio::time::timeout(Duration::from_secs(6), half.write()).await?;
  let crypto_guard = tokio::time::timeout(Duration::from_secs(6), crypto_session.read()).await?;

  let mut payload = read_encrypted_payload(&mut *half_guard, &crypto_guard).await?;

  T::decode(&mut payload).await
}
