/// Статус авторизации
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStatus {
  /// Авторизация успешно пройдена
  Success,

  /// Неожиданный метод авторизации
  UnexpectedMethod,

  /// Данные авторизации полностью отсутствуют
  MissingData,

  /// Авторизация провалена
  Failed,
}

impl AuthStatus {
  /// Метод конвертации байта в `AuthStatus`
  pub fn from_byte(value: u8) -> Option<Self> {
    match value {
      0x00 => Some(Self::Success),
      0x01 => Some(Self::UnexpectedMethod),
      0x02 => Some(Self::MissingData),
      0x03 => Some(Self::Failed),
      _ => None,
    }
  }

  /// Метод конвертации `AuthStatus` в байт
  pub fn to_byte(&self) -> u8 {
    match self {
      Self::Success => 0x00,
      Self::UnexpectedMethod => 0x01,
      Self::MissingData => 0x02,
      Self::Failed => 0x03,
    }
  }
}
