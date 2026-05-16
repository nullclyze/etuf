use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::RwLock;

use crate::protocol::CryptoSession;

/// Структура подключения клиента
pub struct Connection {
  /// IP-адрес клиента
  pub addr: SocketAddr,

  /// Часть сокета для чтения данных
  pub read_half: Arc<RwLock<OwnedReadHalf>>,

  /// Часть сокета для записи данных
  pub write_half: Arc<RwLock<OwnedWriteHalf>>,

  /// Криптографическая сессия
  pub crypto_session: Arc<RwLock<CryptoSession>>,
}

impl Connection {
  /// Метод закрытия соединения
  pub async fn close(&self) -> std::io::Result<()> {
    let mut guard = tokio::time::timeout(Duration::from_secs(6), self.write_half.write()).await?;
    guard.shutdown().await
  }
}
