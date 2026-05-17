# Etuf

An efficient and secure protocol for client-server interaction, written in Rust.

# Features

- **Efficiency:** This protocol aims to be efficient, all operations are limited by timeouts.
- **Security:** This protocol provides asymmetric encryption.
- **Authorization:** This protocol has two authorization methods.
- **Simplicity:** Logic of this protocol is quite simple.

# Examples

All current examples can be found here: [browse](https://github.com/nullclyze/etuf/tree/main/examples)

## Simple ping-pong

**First, let's include dependency in `Cargo.toml`:**
```toml
[dependencies]
etuf = { git = "https://github.com/nullclyze/etuf", features = ["all"] }
```

**Now let's write the code:**
```rust
use std::time::Duration;

use etuf::client::Client;
use etuf::protocol::read::read_encrypted_payload_rw;
use etuf::protocol::write::write_encrypted_payload_rw;
use etuf::server::{Connection, Server, ServerMode};

#[tokio::main]
async fn main() -> std::io::Result<()> {
  tokio::spawn(async move {
    // Создаём обработчик подключений (или же клиентов)
    let handler = async |conn: Connection| {
      let mut is_first = true;

      loop {
        if !is_first {
          // Ждём зашифрованное сообщение от клиента
          let client_msg = read_encrypted_payload_rw(&conn.read_half, &conn.crypto_session).await?;
          println!("[client -> server]: {}", String::from_utf8_lossy(&client_msg));
        } else {
          is_first = false;
        }

        // Отправляем зашифрованное сообщение клиенту
        write_encrypted_payload_rw(&conn.write_half, b"ping!", &conn.crypto_session).await?;
      }
    };

    // Создаём сервер
    let mut server = Server::new()
      .bind("127.0.0.1:47329")
      .with_handler(handler)
      .with_mode(ServerMode::Basic);

    // Запускаем сервер
    match server.run().await {
      Ok(_) => {}
      Err(e) => println!("Ошибка запуска сервера: {}", e),
    }
  });

  // Ждём пока сервер запустится
  tokio::time::sleep(Duration::from_secs(3)).await;

  // Создаём клиента
  let mut client = Client::new();

  // Подключаем клиента к серверу
  match client.connect("127.0.0.1:47329").await {
    Ok(_) => {
      loop {
        // Ждём зашифрованное сообщение от сервера
        let server_msg = client.read_encrypted_payload().await?;
        println!("[server -> client]: {}", String::from_utf8_lossy(&server_msg));

        // Ждём немного
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Отправляем ответное сообщение серверу
        client.write_encrypted_payload(b"pong!").await?;
      }
    }
    Err(e) => println!("Ошибка подключения клиента: {}", e),
  }

  Ok(())
}
```