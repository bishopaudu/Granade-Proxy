use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

/// Manages a spawned `tor` process and its control connection.
pub struct TorController {
    child: Child,
    control_stream: BufReader<TcpStream>,
     #[allow(dead_code)]
    pub control_port: u16,
}

const COOKIE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const COOKIE_POLL_INTERVAL: Duration = Duration::from_millis(200);

impl TorController {
    /// Spawns `tor`, waits for its control port to become usable,
    /// authenticates via the cookie file, and returns a ready
    /// controller. `data_dir` is where tor will keep its state
    /// (including the cookie file) - we own this directory.
    pub async fn spawn(data_dir: PathBuf, control_port: u16) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&data_dir)?;

        // Passing config as CLI args rather than a torrc file - fewer
        // moving parts, and every value is visible right here instead
        // of hidden in a generated file on disk.
        let child = Command::new("tor")
            .arg("--DataDirectory")
            .arg(&data_dir)
            .arg("--ControlPort")
            .arg(control_port.to_string())
            .arg("--CookieAuthentication")
            .arg("1")
            .arg("--SocksPort")
            .arg("0") // we don't need outbound SOCKS for hosting-only use
            .kill_on_drop(true) // if our process dies, tor dies with it
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("failed to spawn 'tor' - is it installed and on PATH? ({e})")
            })?;

        let cookie_path = data_dir.join("control_auth_cookie");
        let cookie = Self::wait_for_cookie(&cookie_path).await?;

        let stream = TcpStream::connect(("127.0.0.1", control_port)).await?;
        let mut control_stream = BufReader::new(stream);

        Self::authenticate(&mut control_stream, &cookie).await?;

        Ok(Self {
            child,
            control_stream,
            control_port,
        })
    }

    /// Polls for the cookie file's existence, since tor writes it
    /// partway through its own startup, not instantly at spawn time.
    async fn wait_for_cookie(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + COOKIE_WAIT_TIMEOUT;
        loop {
            if let Ok(bytes) = tokio::fs::read(path).await {
                return Ok(bytes);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out after {COOKIE_WAIT_TIMEOUT:?} waiting for tor's cookie file at {path:?} - check tor's bootstrap succeeded"
                );
            }
            sleep(COOKIE_POLL_INTERVAL).await;
        }
    }

    async fn authenticate(
        stream: &mut BufReader<TcpStream>,
        cookie: &[u8],
    ) -> anyhow::Result<()> {
        let hex_cookie = hex::encode(cookie);
        let cmd = format!("AUTHENTICATE {hex_cookie}\r\n");
        stream.get_mut().write_all(cmd.as_bytes()).await?;

        let mut line = String::new();
        stream.read_line(&mut line).await?;

        if !line.starts_with("250") {
            anyhow::bail!("authentication failed: {}", line.trim());
        }
        Ok(())
    }

    /// Sends ADD_ONION and returns the resulting .onion address
    /// (without the ".onion" suffix - tor's response is just the
    /// service ID).
    pub async fn add_onion(&mut self, target_port: u16, local_addr: &str) -> anyhow::Result<String> {
        let cmd = format!("ADD_ONION NEW:BEST Port={target_port},{local_addr}\r\n");
        self.control_stream.get_mut().write_all(cmd.as_bytes()).await?;

        let mut service_id = None;
        loop {
            let mut line = String::new();
            let n = self.control_stream.read_line(&mut line).await?;
            if n == 0 {
                anyhow::bail!("control connection closed unexpectedly during ADD_ONION");
            }
            let line = line.trim();

            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                service_id = Some(id.to_string());
            }
            if line.starts_with("250 ") || line == "250 OK" {
                break; // final line of a multi-line response
            }
            if line.starts_with("5") {
                anyhow::bail!("ADD_ONION failed: {line}");
            }
        }

        service_id.ok_or_else(|| anyhow::anyhow!("ADD_ONION succeeded but no ServiceID was returned"))
    }

    /// Cleanly signals tor to shut down rather than killing it
    /// abruptly - lets it unpublish descriptors and exit gracefully.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        let _ = self
            .control_stream
            .get_mut()
            .write_all(b"SIGNAL HALT\r\n")
            .await;
        let _ = self.child.wait().await;
        Ok(())
    }
}