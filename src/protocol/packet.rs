/// Трейт для описания кодировки / декодировки структуированных данных (пакета)
pub trait Packet
where
  Self: Sized,
{
  /// Метод декодировки данных
  fn decode(payload: &mut bytes::Bytes) -> impl std::future::Future<Output = std::io::Result<Self>> + Send;

  /// Метод кодировки данных
  fn encode(&self) -> impl std::future::Future<Output = bytes::Bytes> + Send;
}
