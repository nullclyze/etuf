/// Статус выполнения команды клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandStatus {
  /// Команда успешно выполнена
  Success,

  /// Не удалось выполнить команду
  Failed,

  /// Команда не поддерживается сервером
  Unsupported,
}

impl CommandStatus {
  /// Метод конвертации байта в `CommandStatus`
  pub fn from_byte(value: u8) -> Option<Self> {
    match value {
      0x00 => Some(Self::Success),
      0x01 => Some(Self::Failed),
      0x02 => Some(Self::Unsupported),
      _ => None,
    }
  }

  /// Метод конвертации `CommandStatus` в байт
  pub fn to_byte(&self) -> u8 {
    match self {
      Self::Success => 0x00,
      Self::Failed => 0x01,
      Self::Unsupported => 0x02,
    }
  }
}
