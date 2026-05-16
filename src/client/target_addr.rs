/// Адрес целевого сервера
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddr {
  pub host: String,
  pub port: u16,
}

impl From<String> for TargetAddr {
  fn from(value: String) -> Self {
    let split = value.split(":").collect::<Vec<&str>>();

    Self {
      host: split.get(0).unwrap_or(&"127.0.0.1").to_string(),
      port: split.get(1).unwrap_or(&"38392").parse().unwrap_or(38392),
    }
  }
}

impl From<&str> for TargetAddr {
  fn from(value: &str) -> Self {
    let split = value.split(":").collect::<Vec<&str>>();

    Self {
      host: split.get(0).unwrap_or(&"127.0.0.1").to_string(),
      port: split.get(1).unwrap_or(&"38392").parse().unwrap_or(38392),
    }
  }
}
