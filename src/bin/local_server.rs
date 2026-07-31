use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

use axum::{Router, routing::get};

#[tokio::main]
async fn main(){
    tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();



    let counter = Arc::new(AtomicU64::new(0));

 let handler = {
    let counter = counter.clone();
    move || {
        let counter = counter.clone();

        async move {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                tracing::info!("received request #{n}");

 format!("Hello from grenade proxy local server! #{n}\n")

        }
    }
};

    let app = Router::new().route("/", get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
    .await
    .expect("failed to bind to 127.0.0.1:3000 - is the port already in use?");
tracing::info!("local server listening on http http://127.0.0.1:3000");
axum::serve(listener,app).await.expect("server error");

}