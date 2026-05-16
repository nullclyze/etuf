use bytes::{BufMut, Bytes, BytesMut};

/// Структура данных базовой авторизации
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
  username: String,
  password: String,
}

impl Auth {
  /// Метод создания авторизации
  pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
    Self {
      username: username.into(),
      password: password.into(),
    }
  }

  /// Метод получения юзернейма
  pub fn username(&self) -> &str {
    &self.username
  }

  /// Метод получения байтов юзернейма
  pub fn username_bytes(&self) -> &[u8] {
    &self.username.as_bytes()
  }

  /// Метод получения пароля
  pub fn password(&self) -> &str {
    &self.password
  }

  /// Метод получения байтов пароля
  pub fn password_bytes(&self) -> &[u8] {
    &self.password.as_bytes()
  }

  /// Метод конвертации `Auth` в `Bytes`
  pub fn to_bytes(&self) -> Bytes {
    let mut bytes = BytesMut::with_capacity(1);
    bytes.put_u8(self.username.len() as u8);
    bytes.put_slice(self.username_bytes());
    bytes.put_u8(self.password.len() as u8);
    bytes.put_slice(self.password_bytes());
    bytes.freeze()
  }
}
