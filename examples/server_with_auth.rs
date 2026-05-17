use etuf::protocol::types::Auth;
use etuf::server::Server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
  // Запускаем сервер с авторизацией на 127.0.0.1:38392
  Server::new().with_auth(Auth::new("admin", "qwe123")).run().await

  // Важно: чтобы к данному серверу мог подключиться клиент, у
  // него должны быть данные авторизации (юзернейм и пароль)
}
