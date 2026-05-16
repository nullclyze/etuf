use std::io::{Error, ErrorKind};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::PublicKey;

use crate::client::TargetAddr;
use crate::protocol::packets::{AuthRequest, AuthResponse, ClientGreet, CommandRequest, CommandResponse, PublicKeyExchange, ServerGreet};
use crate::protocol::read::{read_encrypted_packet, read_encrypted_payload, read_packet, read_payload};
use crate::protocol::types::{Auth, AuthMethod, AuthStatus, ClientCommand, CommandStatus};
use crate::protocol::write::{write_encrypted_packet, write_encrypted_payload, write_packet, write_payload};
use crate::protocol::{CryptoSession, KeyExchange, Packet};
use crate::version::PROTOCOL_VERSION;

/// Структура клиента
pub struct Client {
  auth: Option<Auth>,
  require_auth: bool,
  socket: Option<TcpStream>,
  target_addr: Option<TargetAddr>,
  crypto_session: CryptoSession,
}

impl Client {
  /// Метод создания клиента
  pub fn new() -> Self {
    Self {
      auth: None,
      require_auth: false,
      socket: None,
      target_addr: None,
      crypto_session: CryptoSession::new(),
    }
  }

  /// Метод установки авторизации
  pub fn with_auth(mut self, auth: Auth) -> Self {
    self.auth = Some(auth);
    self
  }

  /// Метод установки целевого адреса
  pub fn with_target_addr(mut self, target_addr: impl Into<TargetAddr>) -> Self {
    self.target_addr = Some(target_addr.into());
    self
  }

  /// Метод подключения клиента к серверу
  pub async fn connect(&mut self, addr: impl Into<String>) -> std::io::Result<()> {
    let mut socket = TcpStream::connect(addr.into()).await?;

    self.handshake(&mut socket).await?;
    self.authorize(&mut socket).await?;
    self.encrypt(&mut socket).await?;
    self.command(&mut socket, self.target_addr.clone()).await?;

    self.socket = Some(socket);

    Ok(())
  }

  /// Метод обработки рукопожатия с сервером
  pub async fn handshake(&mut self, socket: &mut TcpStream) -> std::io::Result<()> {
    let client_greet = ClientGreet { version: PROTOCOL_VERSION };
    write_packet(socket, &client_greet).await?;

    let server_greet: ServerGreet = read_packet(socket).await?;

    if server_greet.version != PROTOCOL_VERSION {
      return Err(Error::new(ErrorKind::InvalidData, "incompatible protocol version"));
    }

    self.require_auth = server_greet.require_auth;

    Ok(())
  }

  /// Метод авторизации клиента
  pub async fn authorize(&mut self, socket: &mut TcpStream) -> std::io::Result<()> {
    if self.require_auth {
      let Some(auth) = &self.auth else {
        // Думаю, лучше вернуть ошибку до того как сервер сам отключит клиента
        return Err(Error::new(ErrorKind::InvalidInput, "authorization required"));
      };

      let req = AuthRequest {
        method: AuthMethod::Basic,
        auth: Some(auth.clone()),
      };

      write_packet(socket, &req).await?;

      let resp: AuthResponse = read_packet(socket).await?;

      if resp.status != AuthStatus::Success {
        return Err(Error::new(ErrorKind::InvalidInput, "authorization failed"));
      }
    } else {
      let req = AuthRequest {
        method: AuthMethod::Skip,
        auth: None,
      };

      write_packet(socket, &req).await?;

      let resp: AuthResponse = read_packet(socket).await?;

      if resp.status != AuthStatus::Success {
        return Err(Error::new(ErrorKind::InvalidInput, "authorization failed"));
      }
    }

    Ok(())
  }

  /// Метод шифрования соединения
  pub async fn encrypt(&mut self, socket: &mut TcpStream) -> std::io::Result<()> {
    let server_public_exchange: PublicKeyExchange = read_packet(socket).await?;
    let server_public_key = PublicKey::from(server_public_exchange.public_key);

    let key_exchange = KeyExchange::new();
    let client_public_key = key_exchange.public_key_bytes();

    let server_public_exchange = PublicKeyExchange {
      public_key: client_public_key,
    };

    write_packet(socket, &server_public_exchange).await?;

    let shared_secret = key_exchange.generate_shared_secret(&server_public_key);
    self.crypto_session.setup(&shared_secret);

    Ok(())
  }

  /// Метод шифрования соединения
  pub async fn command(&mut self, socket: &mut TcpStream, target_addr: Option<TargetAddr>) -> std::io::Result<()> {
    if let Some(addr) = target_addr {
      let host = format!("{}:{}", addr.host, addr.port);

      if host.len() > 255 {
        return Err(Error::new(ErrorKind::InvalidData, "host too long"));
      }

      let cmd_req = CommandRequest {
        command: ClientCommand::Proxy,
        target_host: Some(host),
      };

      write_encrypted_packet(socket, &cmd_req, &mut self.crypto_session).await?;
    } else {
      let cmd_req = CommandRequest {
        command: ClientCommand::Direct,
        target_host: None,
      };

      write_encrypted_packet(socket, &cmd_req, &mut self.crypto_session).await?;
    }

    let response: CommandResponse = read_encrypted_packet(socket, &mut self.crypto_session).await?;

    match response.status {
      CommandStatus::Success => Ok(()),
      CommandStatus::Failed => Err(Error::new(ErrorKind::Other, "command execution error")),
      CommandStatus::Unsupported => Err(Error::new(ErrorKind::Unsupported, "command is not supported by server")),
    }
  }

  /// Вспомогательный метод чтения пакета
  pub async fn read_packet<P>(&mut self) -> std::io::Result<P>
  where
    P: Packet,
  {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    read_packet(socket).await
  }

  /// Вспомогательный метод записи пакета
  pub async fn write_packet<P>(&mut self, packet: &P) -> std::io::Result<()>
  where
    P: Packet,
  {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    write_packet(socket, packet).await
  }

  /// Вспомогательный метод чтения данных
  pub async fn read_payload(&mut self) -> std::io::Result<Vec<u8>> {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    let payload = read_payload(socket).await?;

    Ok(payload.to_vec())
  }

  /// Вспомогательный метод записи данных
  pub async fn write_payload(&mut self, payload: &[u8]) -> std::io::Result<()> {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    write_payload(socket, payload).await
  }

  /// Вспомогательный метод записи зашифрованного пакета
  pub async fn write_encrypted_packet<P>(&mut self, packet: &P) -> std::io::Result<()>
  where
    P: Packet,
  {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    write_encrypted_packet(socket, packet, &mut self.crypto_session).await
  }

  /// Вспомогательный метод чтения зашифрованного пакета
  pub async fn read_encrypted_packet<P>(&mut self) -> std::io::Result<P>
  where
    P: Packet,
  {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    read_encrypted_packet(socket, &self.crypto_session).await
  }

  /// Вспомогательный метод чтения зашифрованных данных
  pub async fn read_encrypted_payload(&mut self) -> std::io::Result<Vec<u8>> {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    let payload = read_encrypted_payload(socket, &self.crypto_session).await?;

    Ok(payload.to_vec())
  }

  /// Вспомогательный метод записи зашифрованных данных
  pub async fn write_encrypted_payload(&mut self, payload: &[u8]) -> std::io::Result<()> {
    let Some(socket) = &mut self.socket else {
      return Err(Error::new(ErrorKind::NotConnected, "socket is not initialized"));
    };

    write_encrypted_payload(socket, payload, &mut self.crypto_session).await
  }

  /// Метод получения сокета
  pub async fn get_socket(&mut self) -> &mut Option<TcpStream> {
    &mut self.socket
  }

  /// Метод выключения сокета
  pub async fn shutdown(&mut self) -> std::io::Result<()> {
    if let Some(socket) = &mut self.socket {
      socket.shutdown().await?;
    }

    Ok(())
  }
}
