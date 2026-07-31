use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;
use safelog::DisplayRedacted as _;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname("torproxy-demo".parse()?)
        .build()?;

    let Some((onion_service, rend_requests)) = client.launch_onion_service(svc_config)? else {
        anyhow::bail!("onion service is disabled in its config");
    };

    if let Some(addr) = onion_service.onion_address() {
    tracing::info!("onion service is live at: {}", addr.display_unredacted());
    }

    // Wait until Arti confirms the descriptor is published and the
    // introduction points are actually up - not just "we called
    // launch," but "a client trying to reach us right now would
    // succeed." This directly matches the publish phase from Lesson 4.
    let mut status_events = onion_service.status_events();
    while let Some(status) = status_events.next().await {
        if status.state().is_fully_reachable() {
            tracing::info!("onion service confirmed reachable");
            break;
        }
    }

    let mut stream_requests = std::pin::pin!(tor_hsservice::handle_rend_requests(rend_requests));

    while let Some(stream_request) = stream_requests.next().await {
        tokio::spawn(async move {
            if let Err(e) = handle_stream_request(stream_request).await {
                tracing::warn!("error handling stream: {e}");
            }
        });
    }

    Ok(())
}

async fn handle_stream_request(stream_request: StreamRequest) -> anyhow::Result<()> {
    match stream_request.request() {
        // Port 80 is the port the .onion address itself is reachable
        // on - not the port your local server runs on. Those are
        // deliberately decoupled: your onion service's public "port"
        // and your local server's actual port are two separate
        // things, connected only by this proxying code.
        IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
            let mut onion_stream = stream_request.accept(Connected::new_empty()).await?;
            let mut local_stream = TcpStream::connect("127.0.0.1:3000").await?;
            copy_bidirectional(&mut onion_stream, &mut local_stream).await?;
        }
        _ => {
            // Anything on a port we don't recognize gets its circuit
            // torn down rather than silently ignored - don't leave
            // unexpected connections hanging.
            stream_request.shutdown_circuit()?;
        }
    }
    Ok(())
}