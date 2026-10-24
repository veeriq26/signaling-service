use std::{env, net::SocketAddr, time::Duration};

use axum_server::tls_rustls::RustlsConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use veeriq_signaling::ServiceState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let mode = server_mode_from_environment()?;
    let shutdown = CancellationToken::new();
    let turn_credentials = veeriq_signaling::TurnCredentialProvider::from_environment()?;
    let state = ServiceState::new(shutdown.clone()).with_turn_credentials(turn_credentials);
    let app = state.router();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal_shutdown.cancel();
    });

    match mode {
        ServerMode::Tls {
            bind,
            certificate,
            private_key,
        } => {
            let tls = RustlsConfig::from_pem_file(certificate, private_key).await?;
            let handle = axum_server::Handle::new();
            let graceful_handle = handle.clone();
            let graceful_shutdown = shutdown.clone();
            tokio::spawn(async move {
                graceful_shutdown.cancelled().await;
                graceful_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            tracing::info!(%bind, "starting TLS-only signaling service");
            axum_server::bind_rustls(bind, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        ServerMode::ReverseProxy { bind } => {
            let listener = TcpListener::bind(bind).await?;
            tracing::info!(%bind, "starting signaling service behind trusted TLS reverse proxy");
            let graceful_shutdown = shutdown.clone();
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    graceful_shutdown.cancelled().await;
                })
                .await?;
        }
    }
    shutdown.cancel();
    Ok(())
}

enum ServerMode {
    Tls {
        bind: SocketAddr,
        certificate: String,
        private_key: String,
    },
    ReverseProxy {
        bind: SocketAddr,
    },
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    tracing::error!(%error, "could not register SIGTERM handler");
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(%error, "could not receive Ctrl-C signal");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "could not receive Ctrl-C signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_mode_binds_all_interfaces_on_platform_port() {
        assert!(matches!(
            parse_server_mode(
                None,
                None,
                Some("true"),
                Some("10000"),
                None,
            )
            .unwrap(),
            ServerMode::ReverseProxy { bind } if bind == "0.0.0.0:10000".parse().unwrap()
        ));
    }

    #[test]
    fn proxy_mode_requires_explicit_opt_in_and_valid_port() {
        assert!(parse_server_mode(None, None, None, Some("10000"), None).is_err());
        assert!(parse_server_mode(None, None, Some("true"), None, None).is_err());
        assert!(parse_server_mode(None, None, Some("true"), Some("0"), None).is_err());
        assert!(parse_server_mode(None, None, Some("true"), Some("not-a-port"), None).is_err());
    }

    #[test]
    fn tls_mode_requires_both_certificate_paths_and_preserves_loopback_default() {
        assert!(parse_server_mode(Some("cert.pem"), None, None, None, None).is_err());
        assert!(matches!(
            parse_server_mode(Some("cert.pem"), Some("key.pem"), None, None, None).unwrap(),
            ServerMode::Tls { bind, .. } if bind == "127.0.0.1:8443".parse().unwrap()
        ));
    }

    #[test]
    fn proxy_mode_rejects_tls_paths() {
        assert!(
            parse_server_mode(
                Some("cert.pem"),
                Some("key.pem"),
                Some("true"),
                Some("10000"),
                None,
            )
            .is_err()
        );
    }
}

fn parse_server_mode(
    certificate: Option<&str>,
    private_key: Option<&str>,
    proxy_tls: Option<&str>,
    port: Option<&str>,
    bind_override: Option<&str>,
) -> Result<ServerMode, Box<dyn std::error::Error>> {
    if proxy_tls == Some("true") {
        if certificate.is_some() || private_key.is_some() {
            return Err("proxy TLS mode cannot be combined with certificate/key paths".into());
        }
        let port = port
            .ok_or("PORT must be provided when proxy TLS mode is enabled")?
            .parse::<u16>()?;
        if port == 0 {
            return Err("PORT must be between 1 and 65535".into());
        }
        return Ok(ServerMode::ReverseProxy {
            bind: SocketAddr::from(([0, 0, 0, 0], port)),
        });
    }
    if certificate.is_some() != private_key.is_some() {
        return Err("TLS certificate and private key must be configured together".into());
    }
    let (Some(certificate), Some(private_key)) = (certificate, private_key) else {
        return Err("TLS paths or explicit proxy TLS mode are required".into());
    };
    let bind = bind_override
        .unwrap_or("127.0.0.1:8443")
        .parse::<SocketAddr>()?;
    Ok(ServerMode::Tls {
        bind,
        certificate: certificate.into(),
        private_key: private_key.into(),
    })
}

fn server_mode_from_environment() -> Result<ServerMode, Box<dyn std::error::Error>> {
    let certificate = optional_env("VEERIQ_SIGNAL_CERT")?;
    let private_key = optional_env("VEERIQ_SIGNAL_KEY")?;
    let proxy_tls = optional_env("VEERIQ_SIGNAL_PROXY_TLS")?;
    let port = optional_env("PORT")?;
    let bind = optional_env("VEERIQ_SIGNAL_BIND")?;
    parse_server_mode(
        certificate.as_deref(),
        private_key.as_deref(),
        proxy_tls.as_deref(),
        port.as_deref(),
        bind.as_deref(),
    )
}

fn optional_env(name: &str) -> Result<Option<String>, std::env::VarError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error),
    }
}
