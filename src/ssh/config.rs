use std::fmt;

pub const DEFAULT_PORT: u16 = 22;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_AUTHENTICATION_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_CHANNELS: usize = 8;
pub const DEFAULT_MAX_PENDING_OPERATIONS: usize = 64;
pub const DEFAULT_QUEUE_TIMEOUT_MS: u64 = 30_000;

/// The strict server identity policy selected for a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Match a bounded in-memory OpenSSH known_hosts document.
    KnownHosts(KnownHostsSource),
    /// Accept only one of these `SHA256:` fingerprints.
    Pinned(Vec<String>),
}

#[derive(Clone, PartialEq, Eq)]
pub struct KnownHostsSource(Vec<u8>);

impl KnownHostsSource {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KnownHostsSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnownHostsSource")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// A secret accepted by the SSH authentication protocol.
#[derive(Clone, PartialEq, Eq)]
pub enum Secret {
    Text(String),
    Bytes(Vec<u8>),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text([REDACTED])"),
            Self::Bytes(bytes) => f.debug_tuple("Bytes").field(&bytes.len()).finish(),
        }
    }
}

impl Secret {
    pub fn as_utf8(&self) -> Result<std::borrow::Cow<'_, str>, &'static str> {
        match self {
            Secret::Text(value) => Ok(std::borrow::Cow::Borrowed(value)),
            Secret::Bytes(value) => std::str::from_utf8(value)
                .map(std::borrow::Cow::Borrowed)
                .map_err(|_| "SSH secret bytes must be valid UTF-8"),
        }
    }
}

/// The explicit authentication method. There is intentionally no fallback.
#[derive(Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Secret),
    PrivateKey {
        key: Vec<u8>,
        passphrase: Option<Secret>,
    },
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(secret) => f.debug_tuple("Password").field(secret).finish(),
            Self::PrivateKey { key, passphrase } => f
                .debug_struct("PrivateKey")
                .field("key_len", &key.len())
                .field("passphrase", passphrase)
                .finish(),
        }
    }
}

/// Validated, owned SSH configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub host_key: HostKeyPolicy,
    pub auth: Auth,
    pub connect_timeout_ms: u64,
    pub authentication_timeout_ms: u64,
    pub max_channels: usize,
    pub max_pending_operations: usize,
    pub queue_timeout_ms: u64,
}

/// The connection and host-verification inputs needed before any authentication
/// secret is resolved.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub host_key: HostKeyPolicy,
    pub connect_timeout_ms: u64,
    pub output_budget: crate::process::OutputBudget,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hostname: String,
        port: u16,
        username: String,
        host_key: HostKeyPolicy,
        auth: Auth,
        connect_timeout_ms: u64,
        authentication_timeout_ms: u64,
        max_channels: usize,
        max_pending_operations: usize,
        queue_timeout_ms: u64,
    ) -> Result<Self, &'static str> {
        validate_text(&hostname, "hostname")?;
        validate_text(&username, "username")?;
        if port == 0 {
            return Err("port must be from 1 to 65535");
        }
        if connect_timeout_ms == 0 || authentication_timeout_ms == 0 || queue_timeout_ms == 0 {
            return Err("timeouts must be positive integers");
        }
        if max_channels == 0 || max_pending_operations == 0 {
            return Err("operation limits must be positive integers");
        }
        match &host_key {
            HostKeyPolicy::KnownHosts(source) if source.as_bytes().is_empty() => {
                return Err("known_hosts contents must not be empty");
            }
            HostKeyPolicy::Pinned(pins) if pins.is_empty() => {
                return Err("host key pins must not be empty");
            }
            HostKeyPolicy::Pinned(pins) => {
                for pin in pins {
                    if !pin.starts_with("SHA256:") || pin.len() <= "SHA256:".len() {
                        return Err("host key pins must be SHA256 fingerprints");
                    }
                }
            }
            HostKeyPolicy::KnownHosts(_) => {}
        }
        match &auth {
            Auth::Password(secret) => {
                secret.as_utf8()?;
            }
            Auth::PrivateKey { key, passphrase } => {
                if key.is_empty() {
                    return Err("private key must not be empty");
                }
                if let Some(passphrase) = passphrase {
                    passphrase.as_utf8()?;
                }
            }
        }
        Ok(Self {
            hostname,
            port,
            username,
            host_key,
            auth,
            connect_timeout_ms,
            authentication_timeout_ms,
            max_channels,
            max_pending_operations,
            queue_timeout_ms,
        })
    }

    pub fn transport(&self) -> TransportConfig {
        TransportConfig {
            hostname: self.hostname.clone(),
            port: self.port,
            username: self.username.clone(),
            host_key: self.host_key.clone(),
            connect_timeout_ms: self.connect_timeout_ms,
            output_budget: crate::process::OutputBudget::default(),
        }
    }
}

fn validate_text(value: &str, name: &'static str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err(match name {
            "hostname" => "hostname must not be empty",
            _ => "username must not be empty",
        });
    }
    if value.as_bytes().contains(&0) {
        return Err(match name {
            "hostname" => "hostname must not contain NUL",
            _ => "username must not contain NUL",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_debug_output_redacts_secrets() {
        let password = Auth::Password(Secret::Text("password-sentinel".into()));
        let password_debug = format!("{password:?}");
        assert!(!password_debug.contains("password-sentinel"));
        assert!(password_debug.contains("REDACTED"));

        let private_key = Auth::PrivateKey {
            key: b"private-key-sentinel".to_vec(),
            passphrase: Some(Secret::Bytes(b"passphrase-sentinel".to_vec())),
        };
        let private_key_debug = format!("{private_key:?}");
        assert!(!private_key_debug.contains("private-key-sentinel"));
        assert!(!private_key_debug.contains("passphrase-sentinel"));
        assert!(private_key_debug.contains("key_len: 20"));
        assert!(private_key_debug.contains("Bytes(19)"));
    }
}
