use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const DEFAULT_CREDENTIAL_TTL_SECONDS: u64 = 12 * 60 * 60;
const MIN_CREDENTIAL_TTL_SECONDS: u64 = 5 * 60;
const MAX_CREDENTIAL_TTL_SECONDS: u64 = 24 * 60 * 60;
const MIN_SHARED_SECRET_BYTES: usize = 32;
const MAX_ICE_URLS: usize = 8;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IceServerCredential {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone)]
pub struct TurnCredentialProvider {
    urls: Vec<String>,
    shared_secret: Vec<u8>,
    ttl_seconds: u64,
}

impl TurnCredentialProvider {
    pub fn from_environment() -> Result<Option<Self>, String> {
        let urls = match env::var("VEERIQ_ICE_URLS") {
            Ok(urls) => urls,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err("VEERIQ_ICE_URLS is not valid Unicode".into()),
        };
        let urls = urls
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if urls.is_empty() {
            return Ok(None);
        }
        validate_urls(&urls)?;

        let has_turn = urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"));
        let shared_secret = if has_turn {
            env::var("VEERIQ_TURN_SHARED_SECRET")
                .map_err(|_| "VEERIQ_TURN_SHARED_SECRET is required when TURN URLs are configured")?
                .into_bytes()
        } else {
            Vec::new()
        };
        let ttl_seconds = match env::var("VEERIQ_TURN_CREDENTIAL_TTL_SECS") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|_| "VEERIQ_TURN_CREDENTIAL_TTL_SECS must be a positive integer")?,
            Err(env::VarError::NotPresent) => DEFAULT_CREDENTIAL_TTL_SECONDS,
            Err(_) => return Err("VEERIQ_TURN_CREDENTIAL_TTL_SECS is not valid Unicode".into()),
        };

        Self::new(urls, shared_secret, ttl_seconds).map(Some)
    }

    pub fn new(
        urls: Vec<String>,
        shared_secret: Vec<u8>,
        ttl_seconds: u64,
    ) -> Result<Self, String> {
        validate_urls(&urls)?;
        let has_turn = urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"));
        if has_turn && shared_secret.len() < MIN_SHARED_SECRET_BYTES {
            return Err("TURN shared secret must contain at least 32 bytes".into());
        }
        if !(MIN_CREDENTIAL_TTL_SECONDS..=MAX_CREDENTIAL_TTL_SECONDS).contains(&ttl_seconds) {
            return Err("TURN credential TTL must be between 300 and 86400 seconds".into());
        }
        Ok(Self {
            urls,
            shared_secret,
            ttl_seconds,
        })
    }

    pub fn issue(
        &self,
        fingerprint: &str,
        now_seconds: u64,
    ) -> Result<IceServerCredential, String> {
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("authenticated device fingerprint is invalid".into());
        }
        let has_turn = self
            .urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"));
        let (username, credential, expires_at) = if has_turn {
            let expires_at = now_seconds
                .checked_add(self.ttl_seconds)
                .ok_or_else(|| "TURN credential expiration overflow".to_owned())?;
            let username = format!("{expires_at}:{fingerprint}");
            let mut mac = HmacSha1::new_from_slice(&self.shared_secret)
                .map_err(|_| "TURN shared secret is invalid")?;
            mac.update(username.as_bytes());
            (
                Some(username),
                Some(STANDARD.encode(mac.finalize().into_bytes())),
                Some(expires_at),
            )
        } else {
            (None, None, None)
        };
        Ok(IceServerCredential {
            urls: self.urls.clone(),
            username,
            credential,
            expires_at,
        })
    }
}

pub fn issue_current(
    provider: &TurnCredentialProvider,
    fingerprint: &str,
) -> Result<IceServerCredential, String> {
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before UNIX epoch")?
        .as_secs();
    provider.issue(fingerprint, now_seconds)
}

fn validate_urls(urls: &[String]) -> Result<(), String> {
    if urls.is_empty() || urls.len() > MAX_ICE_URLS {
        return Err("configure between 1 and 8 ICE URLs".into());
    }
    for url in urls {
        if !valid_ice_url(url) {
            return Err("ICE URL is invalid; use stun(s):host[:port] or turn(s):host:port[?transport=udp|tcp]".into());
        }
    }
    Ok(())
}

fn valid_ice_url(url: &str) -> bool {
    if url.len() > 512
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains('#')
    {
        return false;
    }
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    let is_turn = matches!(scheme, "turn" | "turns");
    if !is_turn && !matches!(scheme, "stun" | "stuns") {
        return false;
    }
    let (authority, query) = match rest.split_once('?') {
        Some((authority, query)) => (authority, Some(query)),
        None => (rest, None),
    };
    if let Some(query) = query {
        if !is_turn || !matches!(query, "transport=udp" | "transport=tcp") {
            return false;
        }
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((ipv6, remainder)) = bracketed.split_once(']') else {
            return false;
        };
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let port = if remainder.is_empty() {
            None
        } else if let Some(port) = remainder.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        };
        (Some(ipv6), port)
    } else {
        if authority.matches(':').count() > 1 {
            return false;
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        (Some(host), port)
    };
    let Some(host) = host else {
        return false;
    };
    if !valid_dns_or_ipv4_host(host) {
        return false;
    }
    match port {
        Some(port) => port.parse::<u16>().is_ok_and(|port| port != 0),
        None => !is_turn,
    }
}

fn valid_dns_or_ipv4_host(host: &str) -> bool {
    host.parse::<std::net::Ipv6Addr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && !host.starts_with('.')
            && !host.ends_with('.')
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_coturn_rest_credentials_for_authenticated_device_and_expiry() {
        let provider = TurnCredentialProvider::new(
            vec!["turn:turn.example.test:3478?transport=udp".into()],
            vec![7; MIN_SHARED_SECRET_BYTES],
            3600,
        )
        .unwrap();
        let fingerprint = "ab".repeat(32);
        let issued = provider.issue(&fingerprint, 1_700_000_000).unwrap();
        let expected_username = format!("1700003600:{fingerprint}");
        let mut mac = HmacSha1::new_from_slice(&[7; MIN_SHARED_SECRET_BYTES]).unwrap();
        mac.update(expected_username.as_bytes());
        assert_eq!(issued.username.as_deref(), Some(expected_username.as_str()));
        assert_eq!(
            issued.credential.as_deref(),
            Some(STANDARD.encode(mac.finalize().into_bytes()).as_str())
        );
        assert_eq!(issued.expires_at, Some(1_700_003_600));
        assert_eq!(
            issued.urls,
            vec!["turn:turn.example.test:3478?transport=udp"]
        );
    }

    #[test]
    fn rejects_missing_secret_short_ttl_invalid_fingerprint_and_bad_urls() {
        assert!(
            TurnCredentialProvider::new(
                vec!["turn:turn.example.test:3478".into()],
                Vec::new(),
                3600,
            )
            .is_err()
        );
        assert!(
            TurnCredentialProvider::new(vec!["stun:stun.example.test:3478".into()], Vec::new(), 1,)
                .is_err()
        );
        assert!(
            TurnCredentialProvider::new(
                vec!["http://example.test".into()],
                vec![7; MIN_SHARED_SECRET_BYTES],
                3600,
            )
            .is_err()
        );
        assert!(
            TurnCredentialProvider::new(
                vec!["turn:turn.example.test:99999".into()],
                vec![7; MIN_SHARED_SECRET_BYTES],
                3600,
            )
            .is_err()
        );
        let provider = TurnCredentialProvider::new(
            vec!["turn:turn.example.test:3478".into()],
            vec![7; MIN_SHARED_SECRET_BYTES],
            3600,
        )
        .unwrap();
        assert!(provider.issue("not-a-fingerprint", 1_700_000_000).is_err());
    }

    #[test]
    fn accepts_stun_only_and_bracketed_ipv6_urls() {
        assert!(
            TurnCredentialProvider::new(vec!["stun:stun.example.test".into()], Vec::new(), 3600,)
                .is_ok()
        );
        assert!(
            TurnCredentialProvider::new(
                vec!["turns:[2001:db8::1]:5349?transport=tcp".into()],
                vec![7; MIN_SHARED_SECRET_BYTES],
                3600,
            )
            .is_ok()
        );
    }
}
