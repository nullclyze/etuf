use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use x25519_dalek::PublicKey;

use crate::protocol::packets::{AuthRequest, AuthResponse, ClientGreet, CommandRequest, CommandResponse, PublicKeyExchange, ServerGreet};
use crate::protocol::read::{read_encrypted_packet_rw, read_packet_rw, read_payload_rw};
use crate::protocol::types::{Auth, AuthMethod, AuthStatus, ClientCommand, CommandStatus};
use crate::protocol::write::{write_encrypted_packet_rw, write_packet_rw, write_payload_rw};
use crate::protocol::{CryptoSession, KeyExchange};
use crate::server::Connection;
use crate::version::PROTOCOL_VERSION;

/// Тип обработчика клиента
pub type Handler = Arc<dyn Fn(Connection) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>> + Send + Sync>;

/// Режим сервера
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMode {
  /// Базовый режим, клиент напрямую общается с сервером без посредников
  Basic,

  /// Режим прокси, сервер является промежуточной точкой между клиентом и целевым сервером
  Proxy,

  /// Мульти режим, сервер может быть использован в режимах `ServerMode::Basic` и `ServerMode::Proxy`
  Multi,
}

impl Default for ServerMode {
  fn default() -> Self {
    Self::Multi
  }
}

/// Структура сервера
pub struct Server {
  addr: String,
  auth: Option<Auth>,
  mode: ServerMode,
  handler: Option<Handler>,
}

impl Server {
  /// Метод создания сервера
  pub fn new() -> Self {
    Self {
      addr: "127.0.0.1:38392".to_string(),
      auth: None,
      mode: ServerMode::Multi,
      handler: None,
    }
  }

  /// Метод установки адреса сервера
  pub fn bind(mut self, addr: impl Into<String>) -> Self {
    self.addr = addr.into();
    self
  }

  /// Метод установки авторизации сервера
  pub fn with_auth(mut self, auth: Auth) -> Self {
    self.auth = Some(auth);
    self
  }

  /// Метод установки обработчика клиентов
  pub fn with_handler<F, O>(mut self, handler: F) -> Self
  where
    F: Fn(Connection) -> O + Send + Sync + 'static,
    O: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
  {
    self.handler = Some(Arc::new(move |conn| Box::pin(handler(conn))));
    self
  }

  /// Метод установки режима сервера
  pub fn with_mode(mut self, mode: ServerMode) -> Self {
    self.mode = mode;
    self
  }

  /// Метод запуска сервера на указанном адресе
  pub async fn run(&mut self) -> std::io::Result<()> {
    let listener = TcpListener::bind(&self.addr).await?;
    let auth = Arc::new(self.auth.clone());

    loop {
      let (socket, addr) = listener.accept().await?;
      let auth_clone = auth.clone();
      let handler_clone = self.handler.clone();
      let mode = self.mode.clone();

      tokio::spawn(Self::process_client(addr, socket, auth_clone, mode, handler_clone));
    }
  }

  /// Метод обработки клиента
  pub async fn process_client(
    addr: SocketAddr,
    socket: TcpStream,
    auth: Arc<Option<Auth>>,
    mode: ServerMode,
    handler: Option<Handler>,
  ) -> std::io::Result<()> {
    let (read_half, write_half) = socket.into_split();

    let conn = Connection {
      addr,
      read_half: Arc::new(RwLock::new(read_half)),
      write_half: Arc::new(RwLock::new(write_half)),
      crypto_session: Arc::new(RwLock::new(CryptoSession::new())),
    };

    Self::process_handshake(&conn, auth.is_some()).await?;
    Self::process_authorization(&conn, auth).await?;
    Self::process_encryption(&conn, &mut *conn.crypto_session.write().await).await?;
    Self::process_command(&conn, mode).await?;

    if let Some(h) = handler {
      h(conn).await?;
    }

    Ok(())
  }

  /// Метод обработки хэндшейка клиента
  pub async fn process_handshake(conn: &Connection, require_auth: bool) -> std::io::Result<()> {
    let client_greet: ClientGreet = read_packet_rw(&conn.read_half).await?;

    let server_greet = ServerGreet {
      version: PROTOCOL_VERSION,
      require_auth: require_auth,
    };

    write_packet_rw(&conn.write_half, &server_greet).await?;

    if client_greet.version != PROTOCOL_VERSION {
      return Err(Error::new(ErrorKind::Unsupported, "incompatible protocol version"));
    }

    Ok(())
  }

  /// Метод обработки авторизации клиента
  pub async fn process_authorization(conn: &Connection, possible_auth: Arc<Option<Auth>>) -> std::io::Result<()> {
    let auth_req: AuthRequest = read_packet_rw(&conn.read_half).await?;
    let mut auth_resp = AuthResponse {
      status: AuthStatus::Success,
    };

    if auth_req.method == AuthMethod::Skip && possible_auth.is_none() {
      write_packet_rw(&conn.write_half, &auth_resp).await?;
      return Ok(());
    }

    if auth_req.method == AuthMethod::Skip && possible_auth.is_some() {
      auth_resp.status = AuthStatus::UnexpectedMethod;
      write_packet_rw(&conn.write_half, &auth_resp).await?;
      return Err(Error::new(ErrorKind::InvalidData, "unexpected authorization method"));
    }

    if let Some(server_auth) = possible_auth.as_ref() {
      if let Some(client_auth) = auth_req.auth {
        if client_auth.username() != server_auth.username() || client_auth.password() != server_auth.password() {
          auth_resp.status = AuthStatus::Failed;
          write_packet_rw(&conn.write_half, &auth_resp).await?;
          return Err(Error::new(ErrorKind::InvalidData, "username or password is incorrect"));
        } else {
          write_packet_rw(&conn.write_half, &auth_resp).await?;
        }
      } else {
        auth_resp.status = AuthStatus::MissingData;
        write_packet_rw(&conn.write_half, &auth_resp).await?;
        return Err(Error::new(ErrorKind::InvalidData, "username and password are required"));
      }
    }

    Ok(())
  }

  /// Метод обработки шифрования клиента
  pub async fn process_encryption(conn: &Connection, crypto_session: &mut CryptoSession) -> std::io::Result<()> {
    let key_exchange = KeyExchange::new();
    let server_public_key = key_exchange.public_key_bytes();

    let server_public_exchange = PublicKeyExchange {
      public_key: server_public_key,
    };

    write_packet_rw(&conn.write_half, &server_public_exchange).await?;

    let client_public_exchange: PublicKeyExchange = read_packet_rw(&conn.read_half).await?;
    let client_public_key = PublicKey::from(client_public_exchange.public_key);

    let shared_secret = key_exchange.generate_shared_secret(&client_public_key);
    crypto_session.setup(&shared_secret);

    Ok(())
  }

  /// Метод обработки команды клиента
  pub async fn process_command(conn: &Connection, mode: ServerMode) -> std::io::Result<()> {
    let cmd_req: CommandRequest = {
      let mut crypto_session = conn.crypto_session.write().await;
      read_encrypted_packet_rw(&conn.read_half, &mut crypto_session).await?
    };

    let mut resp = CommandResponse {
      status: CommandStatus::Failed,
    };

    if cmd_req.command == ClientCommand::Direct && (mode == ServerMode::Basic || mode == ServerMode::Multi) {
      resp.status = CommandStatus::Success;
      let mut crypto_session = conn.crypto_session.write().await;
      write_encrypted_packet_rw(&conn.write_half, &resp, &mut crypto_session).await?;
    } else if cmd_req.command == ClientCommand::Proxy && (mode == ServerMode::Proxy || mode == ServerMode::Multi) {
      let Some(target_host) = cmd_req.target_host else {
        let mut crypto_session = conn.crypto_session.write().await;
        write_encrypted_packet_rw(&conn.write_half, &resp, &mut crypto_session).await?;
        return Err(Error::new(ErrorKind::InvalidData, "target host not specified"));
      };

      match TcpStream::connect(&target_host).await {
        Ok(target_stream) => {
          resp.status = CommandStatus::Success;
          write_encrypted_packet_rw(&conn.write_half, &resp, &mut *conn.crypto_session.write().await).await?;
          Self::process_proxy_mode(
            conn.read_half.clone(),
            conn.write_half.clone(),
            target_stream,
            conn.crypto_session.clone(),
          )
          .await?;
        }
        Err(e) => {
          write_encrypted_packet_rw(&conn.write_half, &resp, &mut *conn.crypto_session.write().await).await?;
          return Err(e);
        }
      }
    } else {
      resp.status = CommandStatus::Unsupported;
      write_encrypted_packet_rw(&conn.write_half, &resp, &mut *conn.crypto_session.write().await).await?;
      return Err(Error::new(ErrorKind::Unsupported, "unsupported command"));
    }

    Ok(())
  }

  /// Метод обработки прокси режима (передача данных между клиентом и целевым сервером)
  async fn process_proxy_mode(
    client_read: Arc<RwLock<OwnedReadHalf>>,
    client_write: Arc<RwLock<OwnedWriteHalf>>,
    target_socket: TcpStream,
    crypto_session: Arc<RwLock<CryptoSession>>,
  ) -> std::io::Result<()> {
    let (target_read, target_write) = target_socket.into_split();

    let crypto_client_to_target = crypto_session.clone();
    let crypto_target_to_client = crypto_session.clone();

    let client_to_target = tokio::spawn(Self::forward_client_to_target(client_read, target_write, crypto_client_to_target));
    let target_to_client = tokio::spawn(Self::forward_target_to_client(target_read, client_write, crypto_target_to_client));

    let _ = tokio::try_join!(client_to_target, target_to_client);

    Ok(())
  }

  /// Метод передачи данных от клиента к целевому серверу
  async fn forward_client_to_target(
    client_read: Arc<RwLock<OwnedReadHalf>>,
    mut target_write: OwnedWriteHalf,
    crypto_session: Arc<RwLock<CryptoSession>>,
  ) -> std::io::Result<()> {
    loop {
      let payload = match read_payload_rw(&client_read).await {
        Ok(p) => p,
        Err(_) => break,
      };

      let decrypted = {
        let session = tokio::time::timeout(Duration::from_secs(6), crypto_session.read()).await?;
        session.decrypt(&payload)?
      };

      tokio::time::timeout(Duration::from_secs(14), target_write.write_all(&decrypted)).await??;
      target_write.flush().await?;
    }

    Ok(())
  }

  /// Метод передачи данных от целевого сервера к клиенту
  async fn forward_target_to_client(
    mut target_read: OwnedReadHalf,
    client_write: Arc<RwLock<OwnedWriteHalf>>,
    crypto_session: Arc<RwLock<CryptoSession>>,
  ) -> std::io::Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
      let n = tokio::time::timeout(Duration::from_secs(14), target_read.read(&mut buffer)).await??;

      if n == 0 {
        break;
      }

      let encrypted = {
        let mut session = tokio::time::timeout(Duration::from_secs(6), crypto_session.write()).await?;
        session.encrypt(&buffer[..n])?
      };

      write_payload_rw(&client_write, &encrypted).await?;
    }

    Ok(())
  }
}
