use std::{env, net::SocketAddr, time::Duration};

use axum_server::tls_rustls::RustlsConfig;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use veeriq_signaling::ServiceState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind: SocketAddr = env::var("VEERIQ_SIGNAL_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8443".into())
        .parse()?;
    let certificate = env::var("VEERIQ_SIGNAL_CERT")
        .map_err(|_| "VEERIQ_SIGNAL_CERT must point to a PEM certificate chain")?;
    let private_key = env::var("VEERIQ_SIGNAL_KEY")
        .map_err(|_| "VEERIQ_SIGNAL_KEY must point to a PEM private key")?;
    let tls = RustlsConfig::from_pem_file(certificate, private_key).await?;
    let shutdown = CancellationToken::new();
    let turn_credentials = veeriq_signaling::TurnCredentialProvider::from_environment()?;
    let state = ServiceState::new(shutdown.clone()).with_turn_credentials(turn_credentials);
    let app = state.router();
    let handle = axum_server::Handle::new();
    let signal_shutdown = shutdown.clone();
    let signal_handle = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_shutdown.cancel();
            signal_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });

    tracing::info!(%bind, "starting TLS-only signaling service");
    axum_server::bind_rustls(bind, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;
    shutdown.cancel();
    Ok(())
}
