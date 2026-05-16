use std::time::Duration;

use etuf::client::Client;
use etuf::protocol::write::write_encrypted_payload;
use etuf::server::{Connection, Server, ServerMode};

#[tokio::test]
async fn simple_interact() -> std::io::Result<()> {
  let server_handle = tokio::spawn(async move {
    let handler = async move |conn: Connection| {
      println!("Новое подключение: {:?}", conn.addr);

      write_encrypted_payload(
        &mut *conn.write_half.write().await,
        b"hello",
        &mut *conn.crypto_session.write().await,
      )
      .await?;

      Ok(())
    };

    Server::new().with_mode(ServerMode::Multi).with_handler(handler).run().await
  });

  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(5)).await;

    for _ in 0..5 {
      let mut client = Client::new();

      let _ = client.connect("127.0.0.1:38392").await;

      match client.read_encrypted_payload().await {
        Ok(msg) => println!("Клиент получил сообщение от сервера: {}", String::from_utf8_lossy(&msg)),
        Err(_) => {}
      }
    }
  });

  server_handle.await?
}
