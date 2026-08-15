mod tor_controller;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use tor_controller::TorController;

const MAX_CONCURRENT_CONNECTIONS: usize = 100;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const CONTROL_PORT: u16 = 9051;

/// torproxy: expose one or more local servers as Tor onion services.
#[derive(Parser)]
#[command(name = "torproxy")]
struct Cli {
    /// One or more local addresses to expose, e.g. localhost:3000 localhost:8080
    #[arg(required = true, num_args = 1..)]
    targets: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
       tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();


    let cli = Cli::parse();

    // Fail fast on any bad target before spawning tor at all.
    for target in &cli.targets {
    let _ = tokio::net::lookup_host(target)
        .await
        .map_err(|e| anyhow::anyhow!("invalid target '{target}': {e}"))?;
}

    let data_dir = std::env::temp_dir().join("torproxy-data");
    // One tor daemon, shared across every onion service we create below -
    // one bootstrap cost regardless of how many targets are exposed.
    let mut tor = TorController::spawn(data_dir, CONTROL_PORT).await?;
    tracing::info!("tor daemon bootstrapped and control port ready");

    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut services = JoinSet::new();

    for target in cli.targets {
        // Each target gets its own local listener that tor forwards
        // onion traffic to, and its own ADD_ONION call - but all
        // sharing the same underlying tor process and control connection.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let internal_addr = listener.local_addr()?;

        let onion_id = tor.add_onion(80, &internal_addr.to_string()).await?;
        tracing::info!("exposing {target} at: http://{onion_id}.onion");

        let limiter = connection_limiter.clone();
        let mut shutdown_rx = shutdown_rx.clone();

        services.spawn(async move {
            run_service(target, listener, limiter, &mut shutdown_rx).await;
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown requested, stopping all services...");
    shutdown_tx.send(true).ok();

    while services.join_next().await.is_some() {}

    tor.shutdown().await?;
    tracing::info!("all services stopped.");
    Ok(())
}

async fn run_service(
    target: String,
    listener: TcpListener,
    limiter: Arc<Semaphore>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let Ok((inbound, _)) = accepted else { continue };

                let permit = match limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("[{target}] at max concurrent connections, rejecting");
                        continue;
                    }
                };

                let target = target.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(inbound, &target).await {
                        tracing::warn!("[{target}] error handling connection: {e}");
                    }
                });
            }
        }
    }
    tracing::info!("[{target}] service stopped.");
}

async fn handle_connection(inbound: TcpStream, target: &str) -> anyhow::Result<()> {
    let conn_id = short_id();

    let outbound = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("[{conn_id}] connect to {target} timed out"))??;

    tracing::info!("[{conn_id}] proxying connection to {target}");
    let start = std::time::Instant::now();

    let (a_to_b, b_to_a) =
        copy_bidirectional_with_idle_timeout(inbound, outbound, IDLE_TIMEOUT).await?;

    tracing::info!(
        "[{conn_id}] connection closed after {:?} - {a_to_b} bytes in, {b_to_a} bytes out",
        start.elapsed()
    );
    Ok(())
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
    mut a: A,
    mut b: B,
    idle_timeout: Duration,
) -> anyhow::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];
    let mut a_to_b: u64 = 0;
    let mut b_to_a: u64 = 0;

    loop {
        tokio::select! {
            result = tokio::time::timeout(idle_timeout, a.read(&mut buf_a)) => {
                let n = result.map_err(|_| anyhow::anyhow!("idle timeout waiting on inbound side"))??;
                if n == 0 { break; }
                b.write_all(&buf_a[..n]).await?;
                a_to_b += n as u64;
            }
            result = tokio::time::timeout(idle_timeout, b.read(&mut buf_b)) => {
                let n = result.map_err(|_| anyhow::anyhow!("idle timeout waiting on target side"))??;
                if n == 0 { break; }
                a.write_all(&buf_b[..n]).await?;
                b_to_a += n as u64;
            }
        }
    }
    Ok((a_to_b, b_to_a))
}

fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    return format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() & 0xFFFFFF)
}
