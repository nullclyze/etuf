use std::io::{Error, ErrorKind};

use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::Packet;
use crate::protocol::types::{Auth, AuthMethod};

/// Структура запроса клиента на авторизацию
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
  pub method: AuthMethod,
  pub auth: Option<Auth>,
}

impl Packet for AuthRequest {
  async fn decode(payload: &mut bytes::Bytes) -> std::io::Result<Self> {
    let raw_method = payload.try_get_u8()?;
    let auth_method = AuthMethod::from_byte(raw_method).ok_or(Error::new(ErrorKind::InvalidData, "invalid authorization method"))?;

    let mut basic_auth = None;

    if auth_method == AuthMethod::Basic {
      let username_length = payload.try_get_u8()? as usize;

      if username_length > 64 || username_length < 1 {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect username length"));
      }

      let username_bytes = payload.slice(0..username_length);
      let username = String::from_utf8_lossy(&username_bytes);

      let mut password_template = payload.slice(username_length..);
      let password_length = password_template.try_get_u8()? as usize;

      if password_length > 64 || password_length < 1 {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect password length"));
      }

      let password_bytes = password_template.slice(..password_length);
      let password = String::from_utf8_lossy(&password_bytes);

      basic_auth = Some(Auth::new(username, password));
    }

    Ok(Self {
      method: auth_method,
      auth: basic_auth,
    })
  }

  async fn encode(&self) -> bytes::Bytes {
    if let Some(auth) = &self.auth {
      // 1 байт - метод авторизации
      // 1 байт - длина юзернейма
      // 1 байт - длина пароля
      // N байт - юзернейм / пароль
      let mut payload = BytesMut::with_capacity(3 + auth.username().len() + auth.password().len());
      payload.put_u8(self.method.to_byte());
      payload.put_u8(auth.username().len() as u8);
      payload.put_slice(auth.username_bytes());
      payload.put_u8(auth.password().len() as u8);
      payload.put_slice(auth.password_bytes());
      payload.freeze()
    } else {
      let mut payload = BytesMut::with_capacity(1);
      payload.put_u8(self.method.to_byte());
      payload.freeze()
    }
  }
}
