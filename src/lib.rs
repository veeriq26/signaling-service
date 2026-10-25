use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use futures_util::{SinkExt, StreamExt};
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
const PAIRING_CODE_TTL: Duration = Duration::from_secs(5 * 60);
const PAIRING_REQUEST_TTL: Duration = Duration::from_secs(60);
const PAIRING_RATE_WINDOW: Duration = Duration::from_secs(60);
const PAIRING_REQUEST_ID_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_PAIRING_ATTEMPTS_PER_MINUTE: usize = 5;
const MAX_GLOBAL_PAIRING_ATTEMPTS_PER_MINUTE: usize = 60;
const MAX_GLOBAL_PAIRING_CREATES_PER_MINUTE: usize = 30;
const MAX_PAIRING_CODES: usize = 128;
const MAX_PAIRING_REQUEST_IDS: usize = 2048;

#[derive(Clone)]
pub struct ServiceState {
    connections: Arc<Mutex<HashMap<String, ConnectionHandle>>>,
    slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    turn_credentials: Option<TurnCredentialProvider>,
    pairings: Arc<Mutex<PairingRegistry>>,
}

struct ConnectionHandle {
    sender: mpsc::Sender<Message>,
    connection_id: u64,
    cancel: CancellationToken,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingIdentity {
    fingerprint: String,
    public_key: String,
    display_name: String,
}

#[derive(Clone)]
struct PairingOffer {
    owner: PairingIdentity,
    owner_connection_id: u64,
    expires_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingPairing {
    owner: PairingIdentity,
    requester: PairingIdentity,
    owner_connection_id: u64,
    requester_connection_id: u64,
    expires_at: Instant,
}

#[derive(Default)]
struct PairingRegistry {
    offers: HashMap<String, PairingOffer>,
    pending: HashMap<String, PendingPairing>,
    create_attempts: HashMap<String, VecDeque<Instant>>,
    join_attempts: HashMap<String, VecDeque<Instant>>,
    global_create_attempts: VecDeque<Instant>,
    global_join_attempts: VecDeque<Instant>,
    used_request_ids: HashMap<String, Instant>,
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
    PairingCreate {
        request_id: String,
    },
    PairingJoin {
        request_id: String,
        code: String,
    },
    PairingDecision {
        request_id: String,
        approved: bool,
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
    PairingCode {
        request_id: String,
        code: String,
        expires_at: u64,
    },
    PairingRequest {
        request_id: String,
        peer: PairingIdentity,
        expires_at: u64,
    },
    PairingResult {
        request_id: String,
        status: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer: Option<PairingIdentity>,
    },
    PairingError {
        request_id: String,
        code: &'static str,
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
            pairings: Arc::new(Mutex::new(PairingRegistry::default())),
        }
    }
}

impl PairingRegistry {
    fn prune(&mut self, now: Instant) {
        self.offers.retain(|_, offer| offer.expires_at > now);
        self.used_request_ids
            .retain(|_, expires_at| *expires_at > now);
        for attempts in self.create_attempts.values_mut() {
            prune_attempts(attempts, now);
        }
        self.create_attempts
            .retain(|_, attempts| !attempts.is_empty());
        for attempts in self.join_attempts.values_mut() {
            prune_attempts(attempts, now);
        }
        self.join_attempts
            .retain(|_, attempts| !attempts.is_empty());
        prune_attempts(&mut self.global_create_attempts, now);
        prune_attempts(&mut self.global_join_attempts, now);
    }

    fn remove_connection(
        &mut self,
        fingerprint: &str,
        connection_id: u64,
        now: Instant,
    ) -> Vec<(String, PendingPairing)> {
        self.prune(now);
        self.offers.retain(|_, offer| {
            offer.owner.fingerprint != fingerprint || offer.owner_connection_id != connection_id
        });
        let expired = self
            .pending
            .iter()
            .filter(|(_, request)| {
                (request.owner.fingerprint == fingerprint
                    && request.owner_connection_id == connection_id)
                    || (request.requester.fingerprint == fingerprint
                        && request.requester_connection_id == connection_id)
            })
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|request_id| {
                self.pending
                    .remove(&request_id)
                    .map(|request| (request_id, request))
            })
            .collect()
    }

    fn expire(&mut self, now: Instant) -> Vec<(String, PendingPairing)> {
        self.prune(now);
        let expired = self
            .pending
            .iter()
            .filter(|(_, request)| request.expires_at <= now)
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|request_id| {
                self.pending
                    .remove(&request_id)
                    .map(|request| (request_id, request))
            })
            .collect()
    }

    fn create(
        &mut self,
        owner: PairingIdentity,
        connection_id: u64,
        request_id: &str,
        code: String,
        now: Instant,
    ) -> Result<(), &'static str> {
        self.prune(now);
        let global_attempts = &mut self.global_create_attempts;
        if global_attempts.len() >= MAX_GLOBAL_PAIRING_CREATES_PER_MINUTE {
            return Err("rate-limited");
        }
        global_attempts.push_back(now);
        if !valid_request_id(request_id) {
            return Err("invalid-request");
        }
        let attempts = self
            .create_attempts
            .entry(owner.fingerprint.clone())
            .or_default();
        prune_attempts(attempts, now);
        if attempts.len() >= 3 {
            return Err("rate-limited");
        }
        attempts.push_back(now);
        if !valid_pairing_code(&code)
            || self.offers.len() >= MAX_PAIRING_CODES
            || self.offers.contains_key(&code)
            || self
                .offers
                .values()
                .any(|offer| offer.owner.fingerprint == owner.fingerprint)
            || self.pending.values().any(|request| {
                request.owner.fingerprint == owner.fingerprint
                    || request.requester.fingerprint == owner.fingerprint
            })
        {
            return Err("pairing-unavailable");
        }
        self.reserve_request_id(request_id, now)?;
        self.offers.insert(
            code,
            PairingOffer {
                owner,
                owner_connection_id: connection_id,
                expires_at: now + PAIRING_CODE_TTL,
            },
        );
        Ok(())
    }

    fn join(
        &mut self,
        requester: PairingIdentity,
        requester_connection_id: u64,
        request_id: &str,
        code: &str,
        now: Instant,
    ) -> Result<PendingPairing, &'static str> {
        self.prune(now);
        if self.global_join_attempts.len() >= MAX_GLOBAL_PAIRING_ATTEMPTS_PER_MINUTE {
            return Err("rate-limited");
        }
        self.global_join_attempts.push_back(now);
        let attempts = self
            .join_attempts
            .entry(requester.fingerprint.clone())
            .or_default();
        prune_attempts(attempts, now);
        if attempts.len() >= MAX_PAIRING_ATTEMPTS_PER_MINUTE {
            return Err("rate-limited");
        }
        attempts.push_back(now);
        if !valid_request_id(request_id) || !valid_pairing_code(code) {
            if !valid_request_id(request_id) {
                return Err("invalid-code");
            }
            self.reserve_request_id(request_id, now)?;
            return Err("invalid-code");
        }
        self.reserve_request_id(request_id, now)?;
        if self.pending.contains_key(request_id) {
            return Err("duplicate-request");
        }
        if self.pending.values().any(|request| {
            request.owner.fingerprint == requester.fingerprint
                || request.requester.fingerprint == requester.fingerprint
        }) {
            return Err("duplicate-request");
        }
        let offer = self.offers.remove(code).ok_or("invalid-or-expired-code")?;
        if offer.owner.fingerprint == requester.fingerprint {
            return Err("invalid-or-expired-code");
        }
        let pending = PendingPairing {
            owner: offer.owner,
            requester,
            owner_connection_id: offer.owner_connection_id,
            requester_connection_id,
            expires_at: now + PAIRING_REQUEST_TTL,
        };
        self.pending.insert(
            request_id.to_owned(),
            PendingPairing {
                owner: pending.owner.clone(),
                requester: pending.requester.clone(),
                owner_connection_id: pending.owner_connection_id,
                requester_connection_id: pending.requester_connection_id,
                expires_at: pending.expires_at,
            },
        );
        Ok(pending)
    }

    fn reserve_request_id(&mut self, request_id: &str, now: Instant) -> Result<(), &'static str> {
        if self.used_request_ids.contains_key(request_id) {
            return Err("duplicate-request");
        }
        if self.used_request_ids.len() >= MAX_PAIRING_REQUEST_IDS {
            return Err("temporarily-unavailable");
        }
        self.used_request_ids
            .insert(request_id.to_owned(), now + PAIRING_REQUEST_ID_RETENTION);
        Ok(())
    }

    fn decide(
        &mut self,
        owner_fingerprint: &str,
        owner_connection_id: u64,
        request_id: &str,
        _approved: bool,
        now: Instant,
    ) -> Result<PendingPairing, &'static str> {
        self.prune(now);
        let request = self.pending.get(request_id).ok_or("pairing-not-pending")?;
        if request.expires_at <= now {
            return Err("pairing-expired");
        }
        if request.owner.fingerprint != owner_fingerprint
            || request.owner_connection_id != owner_connection_id
        {
            return Err("not-pairing-owner");
        }
        self.pending.remove(request_id).ok_or("pairing-not-pending")
    }
}

fn prune_attempts(attempts: &mut VecDeque<Instant>, now: Instant) {
    while attempts
        .front()
        .is_some_and(|at| now.duration_since(*at) >= PAIRING_RATE_WINDOW)
    {
        attempts.pop_front();
    }
}

fn valid_pairing_code(code: &str) -> bool {
    code.len() == 8 && code.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_request_id(request_id: &str) -> bool {
    request_id.len() == 32
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn random_pairing_code() -> Result<String, &'static str> {
    let mut bytes = [0_u8; 4];
    random_fill(&mut bytes).map_err(|_| "temporarily-unavailable")?;
    Ok(format!("{:08}", u32::from_le_bytes(bytes) % 100_000_000))
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

impl ServiceState {
    pub fn with_turn_credentials(mut self, provider: Option<TurnCredentialProvider>) -> Self {
        self.turn_credentials = provider;
        self
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/signal", get(upgrade))
            .with_state(self)
    }
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
    let identity = PairingIdentity {
        fingerprint: fingerprint.clone(),
        public_key: public_key.to_ascii_lowercase(),
        display_name: display_name.clone(),
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
    let connection_cancel = CancellationToken::new();
    let replaced_connection = match state.connections.lock() {
        Ok(mut connections) => Ok(replace_connection(
            &mut connections,
            &fingerprint,
            ConnectionHandle {
                sender,
                connection_id,
                cancel: connection_cancel.clone(),
            },
        )),
        Err(_) => Err("temporarily-unavailable"),
    };
    match replaced_connection {
        Ok(Some(previous)) => previous.cancel.cancel(),
        Ok(None) => {}
        Err(code) => {
            let _ = send_error(&mut socket, code).await;
            return;
        }
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
    let mut cleanup = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            _ = connection_cancel.cancelled() => {
                let _ = send_json(
                    &mut socket,
                    &ServerMessage::Error { code: "connection-replaced" },
                ).await;
                let _ = socket.close().await;
                break;
            }
            _ = cleanup.tick() => cleanup_expired_pairings(&state).await,
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
                if !is_current_connection(&state, &fingerprint, connection_id) {
                    break;
                }
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
                        let Ok(client_message) = serde_json::from_str::<ClientMessage>(text.as_str()) else {
                            let _ = send_error(&mut socket, "invalid-message").await;
                            break;
                        };
                        match client_message {
                            ClientMessage::Relay { target_fingerprint, message } => {
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
                                let target_result = {
                                    match state.connections.lock() {
                                        Ok(connections) => Ok(connections.get(&target_fingerprint)
                                            .map(|handle| handle.sender.clone())),
                                        Err(_) => Err(()),
                                    }
                                };
                                let target = match target_result {
                                    Ok(target) => target,
                                    Err(_) => {
                                        let _ = send_error(&mut socket, "temporarily-unavailable").await;
                                        break;
                                    }
                                };
                                match target {
                                    Some(target) if target.send(payload).await.is_ok() => {}
                                    _ => {
                                        let _ = send_error(&mut socket, "peer-unavailable").await;
                                    }
                                }
                            }
                            ClientMessage::PairingCreate { request_id } => {
                                handle_pairing_create(
                                    &state,
                                    &identity,
                                    connection_id,
                                    &request_id,
                                    &fingerprint,
                                ).await;
                            }
                            ClientMessage::PairingJoin { request_id, code } => {
                                handle_pairing_join(
                                    &state,
                                    &identity,
                                    connection_id,
                                    &request_id,
                                    &code,
                                ).await;
                            }
                            ClientMessage::PairingDecision { request_id, approved } => {
                                handle_pairing_decision(
                                    &state,
                                    &identity,
                                    connection_id,
                                    &request_id,
                                    approved,
                                ).await;
                            }
                            ClientMessage::Authenticate { .. } => {
                                let _ = send_error(&mut socket, "already-authenticated").await;
                                break;
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
    cleanup_disconnected_pairings(&state, &fingerprint, connection_id).await;
}

async fn handle_pairing_create(
    state: &ServiceState,
    owner: &PairingIdentity,
    connection_id: u64,
    request_id: &str,
    fingerprint: &str,
) {
    let now = Instant::now();
    let created = match state.pairings.lock() {
        Ok(mut registry) => {
            let mut result: Result<String, &'static str> = Err("pairing-unavailable");
            for _ in 0..3 {
                let Ok(code) = random_pairing_code() else {
                    result = Err("temporarily-unavailable");
                    break;
                };
                match registry.create(owner.clone(), connection_id, request_id, code.clone(), now) {
                    Ok(()) => {
                        result = Ok(code);
                        break;
                    }
                    Err(error) => result = Err(error),
                }
            }
            result
        }
        Err(_) => Err("temporarily-unavailable"),
    };
    match created {
        Ok(code) => {
            let sent = send_to_connection(
                state,
                fingerprint,
                connection_id,
                ServerMessage::PairingCode {
                    request_id: request_id.to_owned(),
                    code,
                    expires_at: unix_time_seconds() + PAIRING_CODE_TTL.as_secs(),
                },
            )
            .await;
            if !sent {
                if let Ok(mut registry) = state.pairings.lock() {
                    registry
                        .offers
                        .retain(|_, offer| offer.owner.fingerprint != fingerprint);
                }
            }
        }
        Err(code) => {
            send_pairing_error(state, fingerprint, connection_id, request_id, code).await;
        }
    }
}

async fn handle_pairing_join(
    state: &ServiceState,
    requester: &PairingIdentity,
    connection_id: u64,
    request_id: &str,
    code: &str,
) {
    let result = state
        .pairings
        .lock()
        .map_err(|_| "temporarily-unavailable")
        .and_then(|mut registry| {
            registry.join(
                requester.clone(),
                connection_id,
                request_id,
                code,
                Instant::now(),
            )
        });
    match result {
        Ok(pending) => {
            let message = ServerMessage::PairingRequest {
                request_id: request_id.to_owned(),
                peer: pending.requester,
                expires_at: unix_time_seconds() + PAIRING_REQUEST_TTL.as_secs(),
            };
            if !send_to_connection(
                state,
                &pending.owner.fingerprint,
                pending.owner_connection_id,
                message,
            )
            .await
            {
                if let Ok(mut registry) = state.pairings.lock() {
                    registry.pending.remove(request_id);
                }
                send_pairing_error(
                    state,
                    &requester.fingerprint,
                    connection_id,
                    request_id,
                    "peer-unavailable",
                )
                .await;
            }
        }
        Err(code) => {
            send_pairing_error(
                state,
                &requester.fingerprint,
                connection_id,
                request_id,
                code,
            )
            .await;
        }
    }
}

async fn handle_pairing_decision(
    state: &ServiceState,
    owner: &PairingIdentity,
    connection_id: u64,
    request_id: &str,
    approved: bool,
) {
    let result = state
        .pairings
        .lock()
        .map_err(|_| "temporarily-unavailable")
        .and_then(|mut registry| {
            registry.decide(
                &owner.fingerprint,
                connection_id,
                request_id,
                approved,
                Instant::now(),
            )
        });
    let pending = match result {
        Ok(pending) => pending,
        Err(code) => {
            send_pairing_error(state, &owner.fingerprint, connection_id, request_id, code).await;
            return;
        }
    };
    let status = if approved { "approved" } else { "rejected" };
    let owner_result = ServerMessage::PairingResult {
        request_id: request_id.to_owned(),
        status,
        peer: approved.then_some(pending.requester.clone()),
    };
    let requester_result = ServerMessage::PairingResult {
        request_id: request_id.to_owned(),
        status,
        peer: approved.then_some(pending.owner.clone()),
    };
    let _ = send_to_connection(
        state,
        &pending.owner.fingerprint,
        pending.owner_connection_id,
        owner_result,
    )
    .await;
    let _ = send_to_connection(
        state,
        &pending.requester.fingerprint,
        pending.requester_connection_id,
        requester_result,
    )
    .await;
}

async fn cleanup_expired_pairings(state: &ServiceState) {
    let expired = state
        .pairings
        .lock()
        .map(|mut registry| registry.expire(Instant::now()))
        .unwrap_or_default();
    for (request_id, pending) in expired {
        send_pairing_result_to_both(state, &request_id, "expired", pending).await;
    }
}

async fn cleanup_disconnected_pairings(
    state: &ServiceState,
    fingerprint: &str,
    connection_id: u64,
) {
    let removed = state
        .pairings
        .lock()
        .map(|mut registry| registry.remove_connection(fingerprint, connection_id, Instant::now()))
        .unwrap_or_default();
    for (request_id, pending) in removed {
        send_pairing_result_to_both(state, &request_id, "expired", pending).await;
    }
}

async fn send_pairing_result_to_both(
    state: &ServiceState,
    request_id: &str,
    status: &'static str,
    pending: PendingPairing,
) {
    let _ = send_to_connection(
        state,
        &pending.owner.fingerprint,
        pending.owner_connection_id,
        ServerMessage::PairingResult {
            request_id: request_id.to_owned(),
            status,
            peer: None,
        },
    )
    .await;
    let _ = send_to_connection(
        state,
        &pending.requester.fingerprint,
        pending.requester_connection_id,
        ServerMessage::PairingResult {
            request_id: request_id.to_owned(),
            status,
            peer: None,
        },
    )
    .await;
}

async fn send_pairing_error(
    state: &ServiceState,
    fingerprint: &str,
    connection_id: u64,
    request_id: &str,
    code: &'static str,
) {
    let _ = send_to_connection(
        state,
        fingerprint,
        connection_id,
        ServerMessage::PairingError {
            request_id: request_id.to_owned(),
            code,
        },
    )
    .await;
}

async fn send_to_connection(
    state: &ServiceState,
    fingerprint: &str,
    connection_id: u64,
    message: ServerMessage,
) -> bool {
    let sender = state.connections.lock().ok().and_then(|connections| {
        connections.get(fingerprint).and_then(|handle| {
            (handle.connection_id == connection_id).then(|| handle.sender.clone())
        })
    });
    let Some(sender) = sender else {
        return false;
    };
    serde_json::to_string(&message)
        .ok()
        .is_some_and(|payload| sender.try_send(Message::Text(payload.into())).is_ok())
}

fn remove_connection(state: &ServiceState, fingerprint: &str, connection_id: u64) {
    if let Ok(mut connections) = state.connections.lock() {
        remove_connection_from_registry(&mut connections, fingerprint, connection_id);
    }
}

fn remove_connection_from_registry(
    connections: &mut HashMap<String, ConnectionHandle>,
    fingerprint: &str,
    connection_id: u64,
) {
    if connections
        .get(fingerprint)
        .is_some_and(|handle| handle.connection_id == connection_id)
    {
        connections.remove(fingerprint);
    }
}

fn replace_connection(
    connections: &mut HashMap<String, ConnectionHandle>,
    fingerprint: &str,
    connection: ConnectionHandle,
) -> Option<ConnectionHandle> {
    connections.insert(fingerprint.to_owned(), connection)
}

fn is_current_connection(state: &ServiceState, fingerprint: &str, connection_id: u64) -> bool {
    state.connections.lock().ok().and_then(|connections| {
        connections
            .get(fingerprint)
            .map(|handle| handle.connection_id)
    }) == Some(connection_id)
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

    fn identity(seed: u8, display_name: &str) -> PairingIdentity {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        PairingIdentity {
            fingerprint: hex::encode(Sha256::digest(public_key)),
            public_key: hex::encode(public_key),
            display_name: display_name.into(),
        }
    }

    fn request_id(seed: u8) -> String {
        format!("{seed:02x}{}", "0".repeat(30))
    }

    fn create_offer(
        registry: &mut PairingRegistry,
        owner: PairingIdentity,
        connection_id: u64,
        request_id: &str,
        code: &str,
        now: Instant,
    ) {
        registry
            .create(owner, connection_id, request_id, code.to_owned(), now)
            .expect("valid code offer");
    }

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
    fn pairing_approval_is_one_time_and_returns_both_authenticated_identities() {
        let now = Instant::now();
        let owner = identity(1, "Owner PC");
        let requester = identity(2, "Requester PC");
        let mut registry = PairingRegistry::default();
        create_offer(
            &mut registry,
            owner.clone(),
            11,
            &request_id(1),
            "00123456",
            now,
        );

        let pending = registry
            .join(requester.clone(), 22, &request_id(2), "00123456", now)
            .expect("valid one-time pairing code");
        assert_eq!(pending.owner, owner);
        assert_eq!(pending.requester, requester);
        assert_eq!(
            registry
                .decide(&owner.fingerprint, 11, &request_id(2), true, now)
                .expect("owner approval")
                .requester
                .fingerprint,
            identity(2, "Requester PC").fingerprint
        );
        assert_eq!(
            registry.decide(&owner.fingerprint, 11, &request_id(2), true, now),
            Err("pairing-not-pending")
        );
        assert_eq!(
            registry.join(identity(3, "Replay"), 33, &request_id(3), "00123456", now),
            Err("invalid-or-expired-code")
        );
    }

    #[test]
    fn pairing_rejection_is_one_time_and_cannot_be_decided_by_the_requester() {
        let now = Instant::now();
        let owner = identity(4, "Owner");
        let requester = identity(5, "Requester");
        let mut registry = PairingRegistry::default();
        create_offer(
            &mut registry,
            owner.clone(),
            14,
            &request_id(4),
            "00000001",
            now,
        );
        registry
            .join(requester.clone(), 15, &request_id(5), "00000001", now)
            .expect("request");

        assert_eq!(
            registry.decide(&requester.fingerprint, 15, &request_id(5), true, now),
            Err("not-pairing-owner")
        );
        assert_eq!(
            registry
                .decide(&owner.fingerprint, 14, &request_id(5), false, now)
                .expect("owner rejection")
                .requester,
            requester
        );
        assert_eq!(
            registry.decide(&owner.fingerprint, 14, &request_id(5), true, now),
            Err("pairing-not-pending")
        );
    }

    #[test]
    fn pairing_codes_and_requests_expire_and_cleanup_removes_pending_state() {
        let now = Instant::now();
        let owner = identity(6, "Owner");
        let requester = identity(7, "Requester");
        let mut registry = PairingRegistry::default();
        create_offer(
            &mut registry,
            owner.clone(),
            16,
            &request_id(6),
            "12345678",
            now,
        );
        assert_eq!(
            registry.join(
                requester.clone(),
                17,
                &request_id(7),
                "12345678",
                now + PAIRING_CODE_TTL
            ),
            Err("invalid-or-expired-code")
        );

        create_offer(
            &mut registry,
            owner.clone(),
            16,
            &request_id(8),
            "87654321",
            now + PAIRING_CODE_TTL,
        );
        registry
            .join(
                requester.clone(),
                17,
                &request_id(9),
                "87654321",
                now + PAIRING_CODE_TTL,
            )
            .expect("request before expiry");
        let expired = registry.expire(now + PAIRING_CODE_TTL + PAIRING_REQUEST_TTL);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, request_id(9));

        create_offer(
            &mut registry,
            owner.clone(),
            16,
            &request_id(10),
            "11223344",
            now + Duration::from_secs(600),
        );
        registry
            .join(
                requester.clone(),
                17,
                &request_id(11),
                "11223344",
                now + Duration::from_secs(600),
            )
            .expect("request for disconnect cleanup");
        let disconnected =
            registry.remove_connection(&requester.fingerprint, 17, now + Duration::from_secs(601));
        assert_eq!(disconnected.len(), 1);
        assert!(registry.pending.is_empty());
        assert!(registry.offers.is_empty());
    }

    #[test]
    fn stale_connection_cleanup_does_not_remove_replacement_pairing_state() {
        let now = Instant::now();
        let owner = identity(10, "Owner");
        let requester = identity(11, "Requester");
        let mut registry = PairingRegistry::default();
        create_offer(
            &mut registry,
            owner.clone(),
            20,
            &request_id(12),
            "11223344",
            now,
        );
        registry
            .join(requester, 21, &request_id(13), "11223344", now)
            .expect("request on current connections");

        let removed = registry.remove_connection(&owner.fingerprint, 19, now);

        assert!(removed.is_empty());
        assert!(registry.pending.contains_key(&request_id(13)));
    }

    #[test]
    fn replacing_connection_cancels_previous_socket_without_removing_new_entry() {
        let (old_sender, _) = mpsc::channel(1);
        let old_cancel = CancellationToken::new();
        let fingerprint = identity(12, "Device").fingerprint;
        let mut connections = HashMap::from([(
            fingerprint.clone(),
            ConnectionHandle {
                sender: old_sender,
                connection_id: 30,
                cancel: old_cancel.clone(),
            },
        )]);
        let (new_sender, _) = mpsc::channel(1);

        let previous = replace_connection(
            &mut connections,
            &fingerprint,
            ConnectionHandle {
                sender: new_sender,
                connection_id: 31,
                cancel: CancellationToken::new(),
            },
        )
        .expect("previous connection");
        previous.cancel.cancel();
        remove_connection_from_registry(&mut connections, &fingerprint, 30);

        assert!(old_cancel.is_cancelled());
        assert_eq!(connections[&fingerprint].connection_id, 31);
    }

    #[test]
    fn invalid_pairing_inputs_duplicate_requests_and_rate_abuse_fail_closed() {
        let now = Instant::now();
        let owner = identity(8, "Owner");
        let requester = identity(9, "Requester");
        let mut registry = PairingRegistry::default();
        create_offer(
            &mut registry,
            owner.clone(),
            18,
            &request_id(8),
            "00000002",
            now,
        );
        assert_eq!(
            registry.join(requester.clone(), 19, &request_id(9), "1234", now),
            Err("invalid-code")
        );
        assert_eq!(
            registry.join(owner.clone(), 18, &request_id(10), "00000002", now),
            Err("invalid-or-expired-code")
        );
        create_offer(
            &mut registry,
            owner.clone(),
            18,
            &request_id(13),
            "00000002",
            now,
        );
        registry
            .join(requester.clone(), 19, &request_id(11), "00000002", now)
            .expect("first request");

        let second_owner = identity(10, "Second owner");
        create_offer(
            &mut registry,
            second_owner,
            20,
            &request_id(12),
            "00000003",
            now,
        );
        assert_eq!(
            registry.join(requester.clone(), 19, &request_id(11), "00000003", now),
            Err("duplicate-request")
        );

        let rate_limited_requester = identity(11, "Rate requester");
        for n in 0..MAX_PAIRING_ATTEMPTS_PER_MINUTE {
            assert_eq!(
                registry.join(
                    rate_limited_requester.clone(),
                    19,
                    &request_id(60 + n as u8),
                    "not-a-code",
                    now,
                ),
                Err("invalid-code")
            );
        }
        assert_eq!(
            registry.join(
                rate_limited_requester,
                131,
                &request_id(70),
                "00000105",
                now
            ),
            Err("rate-limited")
        );
        assert!(!valid_request_id("NOT-AN-ID"));
        assert!(!valid_pairing_code("1234567x"));
    }

    #[test]
    fn pairing_wire_messages_use_bounded_numeric_codes_and_authenticated_peer_data() {
        let response = ServerMessage::PairingRequest {
            request_id: request_id(1),
            peer: identity(2, "Authenticated requester"),
            expires_at: 1_800_000_060,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["type"], "pairing-request");
        assert_eq!(value["peer"]["displayName"], "Authenticated requester");
        assert_eq!(value["peer"]["fingerprint"].as_str().unwrap().len(), 64);
        assert!(valid_pairing_code("00123456"));
        assert!(!valid_pairing_code("1234567"));
        assert!(!valid_pairing_code("1234567a"));
    }

    #[test]
    fn global_pairing_attempt_cap_rejects_sybil_style_guessing() {
        let now = Instant::now();
        let mut registry = PairingRegistry::default();
        for index in 0..MAX_GLOBAL_PAIRING_ATTEMPTS_PER_MINUTE {
            let requester = identity((index % 200 + 1) as u8, "Requester");
            assert_eq!(
                registry.join(
                    requester,
                    index as u64,
                    &request_id((index % 200 + 1) as u8),
                    "not-a-code",
                    now,
                ),
                Err("invalid-code")
            );
        }
        assert_eq!(
            registry.join(
                identity(250, "Attacker"),
                999,
                &request_id(250),
                "12345678",
                now,
            ),
            Err("rate-limited")
        );
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
