use etuf::protocol::types::Auth;
use etuf::server::{Connection, Server, ServerMode};

#[tokio::test]
async fn run_server() -> std::io::Result<()> {
  let handler = async move |conn: Connection| {
    println!("Новое подключение: {:?}", conn.addr);
    Ok(())
  };

  Server::new()
    .with_auth(Auth::new("user", "pass"))
    .with_mode(ServerMode::Multi)
    .with_handler(handler)
    .run()
    .await
}
