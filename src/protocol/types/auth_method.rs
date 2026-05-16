/// Структура данных авторизации клиента
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
  /// Без авторизации
  Skip,

  /// Базовая авторизация (юзернейм / пароль)
  Basic,
}

impl AuthMethod {
  /// Метод конвертации байта в `AuthMethod`
  pub fn from_byte(value: u8) -> Option<Self> {
    match value {
      0x00 => Some(Self::Skip),
      0x01 => Some(Self::Basic),
      _ => None,
    }
  }

  /// Метод конвертации `AuthMethod` в байт
  pub fn to_byte(&self) -> u8 {
    match self {
      Self::Skip => 0x00,
      Self::Basic => 0x01,
    }
  }
}
