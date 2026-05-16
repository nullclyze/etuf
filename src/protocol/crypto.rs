use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Криптографическая сессия
#[derive(Clone)]
pub struct CryptoSession {
  cipher: Option<Aes256Gcm>,
  nonce_counter: u64,
}

impl CryptoSession {
  /// Метод создания новой сессии
  pub fn new() -> Self {
    Self {
      cipher: None,
      nonce_counter: 0,
    }
  }

  /// Метод инициализации сессии с общим секретом
  pub fn setup(&mut self, shared_secret: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let key = hasher.finalize();

    if let Ok(cipher) = Aes256Gcm::new_from_slice(&key) {
      self.cipher = Some(cipher);
      self.nonce_counter = 0;
    }
  }

  /// Метод проверки инициализации
  pub fn is_initialized(&self) -> bool {
    self.cipher.is_some()
  }

  /// Метод шифрования данных
  pub fn encrypt(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let cipher = self
      .cipher
      .as_ref()
      .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "crypto session not initialized"))?;

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    self.nonce_counter += 1;

    let encrypted = cipher
      .encrypt(nonce, data)
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to encrypt data"))?;

    let mut result = Vec::with_capacity(12 + encrypted.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted);

    Ok(result)
  }

  /// Метод расшифровки данных
  pub fn decrypt(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let cipher = self
      .cipher
      .as_ref()
      .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "crypto session not initialized"))?;

    if data.len() < 12 {
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "insufficient data to decrypt"));
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let encrypted = &data[12..];

    cipher
      .decrypt(nonce, encrypted)
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to decrypt data"))
  }
}

/// Структура обмена ключами
pub struct KeyExchange {
  secret: EphemeralSecret,
  public: PublicKey,
}

impl KeyExchange {
  /// Метод создания нового `KeyExchange`
  pub fn new() -> Self {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    Self { secret, public }
  }

  /// Метод получения публичного ключа
  pub fn public_key(&self) -> &PublicKey {
    &self.public
  }

  /// Метод получения байтов публичного ключа
  pub fn public_key_bytes(&self) -> [u8; 32] {
    self.public.to_bytes()
  }

  /// Метод генерации общего секрета
  pub fn generate_shared_secret(self, public_key: &PublicKey) -> [u8; 32] {
    self.secret.diffie_hellman(public_key).to_bytes()
  }
}
