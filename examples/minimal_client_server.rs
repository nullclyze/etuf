use std::time::Duration;

use etuf::client::Client;
use etuf::server::Server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
  tokio::spawn(async move {
    // Запускаем сервер на 127.0.0.1:38392
    match Server::new().run().await {
      Ok(_) => {}
      Err(e) => println!("Ошибка запуска сервера: {}", e),
    }
  });

  // Ждём пока сервер запустится
  tokio::time::sleep(Duration::from_secs(3)).await;

  // Создаём клиента
  let mut client = Client::new();

  // Подключаем клиента к серверу
  match client.connect("127.0.0.1:38392").await {
    Ok(_) => println!("Клиент успешно подключился к серверу"),
    Err(e) => println!("Ошибка подключения клиента: {}", e),
  }

  Ok(())
}
