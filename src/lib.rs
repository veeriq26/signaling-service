use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::StreamExt;
use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

mod turn_credentials;
pub use turn_credentials::{IceServerCredential, TurnCredentialProvider, issue_current};

const AUTH_CONTEXT: &[u8] = b"VeerIQ Remote signaling authentication v1\0";
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 128;
const MAX_MESSAGES_PER_MINUTE: usize = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DISPLAY_NAME_CHARS: usize = 64;
const MAX_SIGNAL_TEXT_CHARS: usize = 48 * 1024;

#[derive(Clone)]
pub struct ServiceState {
    connections: Arc<Mutex<HashMap<String, ConnectionHandle>>>,
    slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    turn_credentials: Option<TurnCredentialProvider>,
}

struct ConnectionHandle {
    sender: mpsc::Sender<Message>,
    connection_id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ClientMessage {
    Authenticate {
        public_key: String,
        display_name: String,
        signature: String,
    },
    Relay {
        target_fingerprint: String,
        message: PeerSignal,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum PeerSignal {
    AccessRequest {
        request_id: String,
    },
    Challenge {
        request_id: String,
        challenge: String,
    },
    Authentication {
        request_id: String,
        signature: String,
    },
    Decision {
        request_id: String,
        approved: bool,
    },
    Offer {
        request_id: String,
        sdp: String,
    },
    Answer {
        request_id: String,
        sdp: String,
    },
    IceCandidate {
        request_id: String,
        candidate: String,
    },
    SessionStop {
        request_id: String,
    },
}

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ServerMessage {
    Challenge {
        nonce: String,
    },
    Authenticated {
        fingerprint: String,
        #[serde(rename = "iceServers")]
        ice_servers: Vec<IceServerCredential>,
    },
    Relay {
        from_fingerprint: String,
        message: PeerSignal,
    },
    Error {
        code: &'static str,
    },
}

impl ServiceState {
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            shutdown,
            turn_credentials: None,
        }
    }

    pub fn with_turn_credentials(mut self, provider: Option<TurnCredentialProvider>) -> Self {
        self.turn_credentials = provider;
        self
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/signal", get(upgrade))
            .route("/healthz", get(health_check))
            .with_state(self)
    }
}

async fn health_check() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub fn signaling_auth_message(nonce: &[u8; 32]) -> Vec<u8> {
    [AUTH_CONTEXT, nonce.as_slice()].concat()
}

pub fn verify_device_proof(
    public_key_hex: &str,
    signature_hex: &str,
    nonce: &[u8; 32],
) -> Option<String> {
    let public_key: [u8; 32] = hex::decode(public_key_hex).ok()?.try_into().ok()?;
    let signature: [u8; 64] = hex::decode(signature_hex).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&public_key).ok()?;
    let signature = Signature::from_bytes(&signature);
    key.verify_strict(&signaling_auth_message(nonce), &signature)
        .ok()?;
    Some(hex::encode(Sha256::digest(public_key)))
}

async fn upgrade(ws: WebSocketUpgrade, State(state): State<ServiceState>) -> impl IntoResponse {
    if state.slots.available_permits() == 0 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

async fn handle_socket(mut socket: WebSocket, state: ServiceState) {
    let Ok(_permit) = state.slots.clone().try_acquire_owned() else {
        let _ = send_error(&mut socket, "capacity").await;
        return;
    };

    let mut nonce = [0; 32];
    if random_fill(&mut nonce).is_err() {
        let _ = send_error(&mut socket, "temporarily-unavailable").await;
        return;
    }
    if send_json(
        &mut socket,
        &ServerMessage::Challenge {
            nonce: hex::encode(nonce),
        },
    )
    .await
    .is_err()
    {
        return;
    }

    let first = tokio::time::timeout(AUTH_TIMEOUT, socket.next()).await;
    let Some(Ok(Message::Text(text))) = first.ok().flatten() else {
        let _ = send_error(&mut socket, "authentication-required").await;
        return;
    };
    if text.len() > MAX_MESSAGE_BYTES {
        let _ = send_error(&mut socket, "message-too-large").await;
        return;
    }
    let Ok(ClientMessage::Authenticate {
        public_key,
        display_name,
        signature,
    }) = serde_json::from_str(text.as_str())
    else {
        let _ = send_error(&mut socket, "invalid-authentication-message").await;
        return;
    };
    if !valid_display_name(&display_name) {
        let _ = send_error(&mut socket, "invalid-device-name").await;
        return;
    }
    let Some(fingerprint) = verify_device_proof(&public_key, &signature, &nonce) else {
        let _ = send_error(&mut socket, "invalid-device-proof").await;
        return;
    };
    let ice_servers = match state.turn_credentials.as_ref() {
        Some(provider) => match issue_current(provider, &fingerprint) {
            Ok(credentials) => vec![credentials],
            Err(_) => {
                let _ = send_error(&mut socket, "temporarily-unavailable").await;
                return;
            }
        },
        None => Vec::new(),
    };
    let connection_id = u64::from_le_bytes(nonce[..8].try_into().unwrap_or([0; 8]));
    let (sender, mut receiver) = mpsc::channel::<Message>(32);
    let registration = match state.connections.lock() {
        Ok(mut connections) if !connections.contains_key(&fingerprint) => {
            connections.insert(
                fingerprint.clone(),
                ConnectionHandle {
                    sender,
                    connection_id,
                },
            );
            Ok(())
        }
        Ok(_) => Err("device-already-connected"),
        Err(_) => Err("temporarily-unavailable"),
    };
    if let Err(code) = registration {
        let _ = send_error(&mut socket, code).await;
        return;
    }

    if send_json(
        &mut socket,
        &ServerMessage::Authenticated {
            fingerprint: fingerprint.clone(),
            ice_servers,
        },
    )
    .await
    .is_err()
    {
        remove_connection(&state, &fingerprint, connection_id);
        return;
    }

    let mut recent_messages = VecDeque::new();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            outgoing = receiver.recv() => {
                match outgoing {
                    Some(message) => {
                        if socket.send(message).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { break };
                match message {
                    Message::Text(text) => {
                        if text.len() > MAX_MESSAGE_BYTES {
                            let _ = send_error(&mut socket, "message-too-large").await;
                            break;
                        }
                        let now = Instant::now();
                        while recent_messages.front().is_some_and(|at| now.duration_since(*at) > RATE_WINDOW) {
                            recent_messages.pop_front();
                        }
                        if recent_messages.len() >= MAX_MESSAGES_PER_MINUTE {
                            let _ = send_error(&mut socket, "rate-limited").await;
                            break;
                        }
                        recent_messages.push_back(now);
                        let Ok(ClientMessage::Relay { target_fingerprint, message }) =
                            serde_json::from_str(text.as_str())
                        else {
                            let _ = send_error(&mut socket, "invalid-message").await;
                            break;
                        };
                        if !valid_fingerprint(&target_fingerprint) || !valid_signal(&message) {
                            let _ = send_error(&mut socket, "invalid-message").await;
                            break;
                        }
                        let payload = match serde_json::to_string(&ServerMessage::Relay {
                            from_fingerprint: fingerprint.clone(),
                            message,
                        }) {
                            Ok(payload) => Message::Text(payload.into()),
                            Err(_) => {
                                let _ = send_error(&mut socket, "temporarily-unavailable").await;
                                break;
                            }
                        };
                        let (lock_ok, target) = match state.connections.lock() {
                            Ok(connections) => (
                                true,
                                connections.get(&target_fingerprint)
                                    .map(|handle| handle.sender.clone()),
                            ),
                            Err(_) => (false, None),
                        };
                        if !lock_ok {
                            let _ = send_error(&mut socket, "temporarily-unavailable").await;
                            break;
                        };
                        match target {
                            Some(target) if target.send(payload).await.is_ok() => {}
                            _ => {
                                let _ = send_error(&mut socket, "peer-unavailable").await;
                            }
                        }
                    }
                    Message::Ping(payload) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(_) | Message::Pong(_) => {
                        let _ = send_error(&mut socket, "unsupported-message").await;
                        break;
                    }
                }
            }
        }
    }
    remove_connection(&state, &fingerprint, connection_id);
}

fn remove_connection(state: &ServiceState, fingerprint: &str, connection_id: u64) {
    if let Ok(mut connections) = state.connections.lock() {
        if connections
            .get(fingerprint)
            .is_some_and(|handle| handle.connection_id == connection_id)
        {
            connections.remove(fingerprint);
        }
    }
}

fn valid_display_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed.chars().count() <= MAX_DISPLAY_NAME_CHARS
        && !trimmed.chars().any(char::is_control)
}

fn valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64 && fingerprint.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn valid_signal(message: &PeerSignal) -> bool {
    let valid_request_id = |id: &str| {
        !id.is_empty()
            && id.len() <= 128
            && id.chars().all(|character| character.is_ascii_graphic())
    };
    match message {
        PeerSignal::AccessRequest { request_id } | PeerSignal::Decision { request_id, .. } => {
            valid_request_id(request_id)
        }
        PeerSignal::Challenge {
            request_id,
            challenge,
        }
        | PeerSignal::Authentication {
            request_id,
            signature: challenge,
        } => valid_request_id(request_id) && valid_hex_field(challenge, 4096),
        PeerSignal::Offer { request_id, sdp } | PeerSignal::Answer { request_id, sdp } => {
            valid_request_id(request_id)
                && !sdp.is_empty()
                && sdp.len() <= MAX_SIGNAL_TEXT_CHARS
                && !sdp
                    .chars()
                    .any(|character| character.is_control_except_newline())
        }
        PeerSignal::IceCandidate {
            request_id,
            candidate,
        } => {
            valid_request_id(request_id)
                && !candidate.is_empty()
                && candidate.len() <= 2048
                && !candidate.chars().any(char::is_control)
        }
        PeerSignal::SessionStop { request_id } => valid_request_id(request_id),
    }
}

fn valid_hex_field(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value.len() % 2 == 0
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

async fn send_json(
    socket: &mut WebSocket,
    message: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = serde_json::to_string(message)?;
    socket.send(Message::Text(payload.into())).await?;
    Ok(())
}

async fn send_error(socket: &mut WebSocket, code: &'static str) -> Result<(), axum::Error> {
    let payload = serde_json::to_string(&ServerMessage::Error { code }).map_err(|error| {
        axum::Error::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })?;
    socket.send(Message::Text(payload.into())).await
}

trait ControlChar {
    fn is_control_except_newline(self) -> bool;
}

impl ControlChar for char {
    fn is_control_except_newline(self) -> bool {
        self.is_control() && self != '\n' && self != '\r' && self != '\t'
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn verifies_device_proof_and_derives_public_key_fingerprint() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let nonce = [9; 32];
        let signature = key.sign(&signaling_auth_message(&nonce));

        assert_eq!(
            verify_device_proof(
                &hex::encode(key.verifying_key().to_bytes()),
                &hex::encode(signature.to_bytes()),
                &nonce
            ),
            Some(hex::encode(Sha256::digest(key.verifying_key().to_bytes())))
        );
    }

    #[test]
    fn rejects_wrong_key_malformed_hex_and_bad_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other_key = SigningKey::from_bytes(&[8; 32]);
        let nonce = [9; 32];
        let signature = key.sign(&signaling_auth_message(&nonce));

        assert!(verify_device_proof("bad", "bad", &nonce).is_none());
        assert!(
            verify_device_proof(
                &hex::encode(other_key.verifying_key().to_bytes()),
                &hex::encode(signature.to_bytes()),
                &nonce
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_invalid_names_targets_and_signal_payloads() {
        assert!(!valid_display_name(" \n "));
        assert!(!valid_display_name(&"a".repeat(MAX_DISPLAY_NAME_CHARS + 1)));
        assert!(valid_display_name("Windows host"));
        assert!(!valid_fingerprint("not-a-fingerprint"));
        assert!(!valid_signal(&PeerSignal::AccessRequest {
            request_id: "bad id".into()
        }));
        assert!(!valid_signal(&PeerSignal::Offer {
            request_id: "request-1".into(),
            sdp: "offer\u{0000}".into()
        }));
    }

    #[test]
    fn protocol_uses_camel_case_fields_and_kebab_case_message_types() {
        let authentication: ClientMessage = serde_json::from_str(
            r#"{"type":"authenticate","publicKey":"key","displayName":"This PC","signature":"sig"}"#,
        )
        .unwrap();
        assert!(matches!(
            authentication,
            ClientMessage::Authenticate { public_key, .. } if public_key == "key"
        ));

        let relay: ClientMessage = serde_json::from_str(
            r#"{"type":"relay","targetFingerprint":"abc","message":{"type":"ice-candidate","requestId":"r1","candidate":"candidate"}}"#,
        )
        .unwrap();
        assert!(matches!(
            relay,
            ClientMessage::Relay {
                message: PeerSignal::IceCandidate { request_id, .. },
                ..
            } if request_id == "r1"
        ));

        let response = serde_json::to_string(&ServerMessage::Authenticated {
            fingerprint: "abc".into(),
            ice_servers: Vec::new(),
        })
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap(),
            serde_json::json!({"type": "authenticated", "fingerprint": "abc", "iceServers": []})
        );

        let turn = IceServerCredential {
            urls: vec!["turn:turn.example.test:3478?transport=udp".into()],
            username: Some("1700003600:abc".into()),
            credential: Some("base64-hmac".into()),
            expires_at: Some(1_700_003_600),
        };
        assert_eq!(
            serde_json::to_value(turn).unwrap(),
            serde_json::json!({
                "urls": ["turn:turn.example.test:3478?transport=udp"],
                "username": "1700003600:abc",
                "credential": "base64-hmac",
                "expiresAt": 1700003600
            })
        );
    }
}
