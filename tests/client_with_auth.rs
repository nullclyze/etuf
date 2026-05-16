use std::time::Duration;

use etuf::client::Client;
use etuf::protocol::types::Auth;

#[tokio::test]
async fn run_client_basic() -> std::io::Result<()> {
  let mut client = Client::new().with_auth(Auth::new("user", "pass"));

  client.connect("127.0.0.1:38392").await?;

  tokio::time::sleep(Duration::from_secs(5)).await;

  Ok(())
}
