/// Команда клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCommand {
  /// Оставить прямое соединение
  Direct,

  /// Подкючиться к следующему адресу
  Proxy,
}

impl ClientCommand {
  /// Метод конвертации байта в `ClientCommand`
  pub fn from_byte(value: u8) -> Option<Self> {
    match value {
      0x00 => Some(Self::Direct),
      0x01 => Some(Self::Proxy),
      _ => None,
    }
  }

  /// Метод конвертации `ClientCommand` в байт
  pub fn to_byte(&self) -> u8 {
    match self {
      Self::Direct => 0x00,
      Self::Proxy => 0x01,
    }
  }
}
