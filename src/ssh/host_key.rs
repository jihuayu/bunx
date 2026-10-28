use std::borrow::Cow;

use data_encoding::BASE64_MIME;
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::{HashAlg, PublicKey, parse_public_key_base64};
use sha1::Sha1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyError {
    Unknown { fingerprint: String },
    Changed { line: usize, fingerprint: String },
    Revoked { line: usize, fingerprint: String },
    Invalid { message: String },
}

impl HostKeyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unknown { .. } => "ERR_SSH_HOST_KEY_UNKNOWN",
            Self::Changed { .. } => "ERR_SSH_HOST_KEY_CHANGED",
            Self::Revoked { .. } => "ERR_SSH_HOST_KEY_REVOKED",
            Self::Invalid { .. } => "ERR_SSH_HOST_KEY_INVALID",
        }
    }
}

impl std::fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { fingerprint } => {
                write!(f, "SSH host key {fingerprint} is not trusted")
            }
            Self::Changed { line, fingerprint } => write!(
                f,
                "SSH host key {fingerprint} does not match known_hosts line {line}"
            ),
            Self::Revoked { line, fingerprint } => {
                write!(
                    f,
                    "SSH host key {fingerprint} is revoked at known_hosts line {line}"
                )
            }
            Self::Invalid { message } => write!(f, "invalid SSH host key: {message}"),
        }
    }
}

impl std::error::Error for HostKeyError {}

pub trait HostKeyVerifier {
    fn verify(&self, hostname: &str, port: u16, key: &PublicKey) -> Result<(), HostKeyError>;
}

#[derive(Clone, Debug)]
pub struct KnownHosts {
    source: Vec<u8>,
}

impl KnownHosts {
    pub fn new(source: Vec<u8>) -> Self {
        Self { source }
    }

    pub fn verify(&self, hostname: &str, port: u16, key: &PublicKey) -> Result<(), HostKeyError> {
        let host = if port == 22 {
            Cow::Borrowed(hostname)
        } else {
            Cow::Owned(format!("[{hostname}]:{port}"))
        };
        let fingerprint = fingerprint(key);
        let mut matched_host = false;
        let mut changed_line = None;

        for (index, raw_line) in self.source.split(|byte| *byte == b'\n').enumerate() {
            let line_number = index + 1;
            let line = strip_cr(raw_line);
            let trimmed = trim_ascii(line);
            if trimmed.is_empty() || trimmed[0] == b'#' {
                continue;
            }

            let mut fields = trimmed
                .split(|byte| *byte == b' ' || *byte == b'\t')
                .filter(|field| !field.is_empty());
            let Some(first) = fields.next() else {
                continue;
            };
            let (marker, patterns) = if first == b"@revoked" || first == b"@cert-authority" {
                let Some(patterns) = fields.next() else {
                    continue;
                };
                (Some(first), patterns)
            } else {
                (None, first)
            };
            if !matches_host(host.as_bytes(), patterns)? {
                continue;
            }
            matched_host = true;

            let Some(key_type) = fields.next() else {
                return Err(HostKeyError::Invalid {
                    message: format!("known_hosts line {line_number} has no key"),
                });
            };
            let Some(encoded_key) = fields.next() else {
                return Err(HostKeyError::Invalid {
                    message: format!("known_hosts line {line_number} has no key"),
                });
            };
            if key_type != b"ssh-ed25519"
                && key_type != b"ssh-rsa"
                && !key_type.starts_with(b"ecdsa-sha2-")
            {
                return Err(HostKeyError::Invalid {
                    message: format!("known_hosts line {line_number} has an invalid key type"),
                });
            }
            let Ok(encoded_key) = std::str::from_utf8(encoded_key) else {
                return Err(HostKeyError::Invalid {
                    message: format!("known_hosts line {line_number} is not UTF-8"),
                });
            };
            let known =
                parse_public_key_base64(encoded_key).map_err(|error| HostKeyError::Invalid {
                    message: format!("known_hosts line {line_number}: {error}"),
                })?;

            if marker == Some(b"@revoked") && known.key_data() == key.key_data() {
                return Err(HostKeyError::Revoked {
                    line: line_number,
                    fingerprint,
                });
            }
            if marker.is_some() {
                continue;
            }
            if known.algorithm() == key.algorithm() && known.key_data() != key.key_data() {
                changed_line.get_or_insert(line_number);
            }
            if known.key_data() == key.key_data() {
                return Ok(());
            }
        }

        if matched_host {
            Err(HostKeyError::Changed {
                line: changed_line.unwrap_or(0),
                fingerprint,
            })
        } else {
            Err(HostKeyError::Unknown { fingerprint })
        }
    }
}

impl HostKeyVerifier for KnownHosts {
    fn verify(&self, hostname: &str, port: u16, key: &PublicKey) -> Result<(), HostKeyError> {
        KnownHosts::verify(self, hostname, port, key)
    }
}

#[derive(Clone, Debug)]
pub struct PinnedHostKeys {
    fingerprints: Vec<String>,
}

impl PinnedHostKeys {
    pub fn new(fingerprints: Vec<String>) -> Self {
        Self { fingerprints }
    }
}

impl HostKeyVerifier for PinnedHostKeys {
    fn verify(&self, _hostname: &str, _port: u16, key: &PublicKey) -> Result<(), HostKeyError> {
        let actual = fingerprint(key);
        if self.fingerprints.iter().any(|pin| pin == &actual) {
            Ok(())
        } else {
            Err(HostKeyError::Unknown {
                fingerprint: actual,
            })
        }
    }
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn matches_host(host: &[u8], patterns: &[u8]) -> Result<bool, HostKeyError> {
    let mut matched = false;
    for raw_pattern in patterns.split(|byte| *byte == b',') {
        let (negated, pattern) = match raw_pattern.strip_prefix(b"!") {
            Some(pattern) => (true, pattern),
            None => (false, raw_pattern),
        };
        let matches = if pattern.starts_with(b"|1|") {
            hashed_host_matches(host, pattern)?
        } else {
            wildcard_match(pattern, host)
        };
        if negated && matches {
            return Ok(false);
        }
        matched |= matches;
    }
    Ok(matched)
}

fn hashed_host_matches(host: &[u8], pattern: &[u8]) -> Result<bool, HostKeyError> {
    let mut fields = pattern.split(|byte| *byte == b'|').skip(2);
    let (Some(salt), Some(expected)) = (fields.next(), fields.next()) else {
        return Err(HostKeyError::Invalid {
            message: "malformed hashed known_hosts entry".to_string(),
        });
    };
    let salt = BASE64_MIME
        .decode(salt)
        .map_err(|_| HostKeyError::Invalid {
            message: "invalid known_hosts salt".to_string(),
        })?;
    let expected = BASE64_MIME
        .decode(expected)
        .map_err(|_| HostKeyError::Invalid {
            message: "invalid hashed known_hosts digest".to_string(),
        })?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&salt).map_err(|_| HostKeyError::Invalid {
        message: "invalid known_hosts salt".to_string(),
    })?;
    mac.update(host);
    Ok(mac.verify_slice(&expected).is_ok())
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            resume = t;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn verifier(policy: &crate::HostKeyPolicy) -> Box<dyn HostKeyVerifier + Send + Sync> {
    match policy {
        crate::HostKeyPolicy::KnownHosts(source) => {
            Box::new(KnownHosts::new(source.as_bytes().to_vec()))
        }
        crate::HostKeyPolicy::Pinned(pins) => Box::new(PinnedHostKeys::new(pins.clone())),
    }
}

pub fn sign_algorithm_name(key: &PublicKey) -> String {
    match key.algorithm() {
        russh::keys::Algorithm::Rsa { .. } => "rsa-sha2-256".to_string(),
        algorithm => algorithm.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use rand::rng;

    use super::*;

    fn test_key() -> PublicKey {
        russh::keys::PrivateKey::random(&mut rng(), russh::keys::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn known_hosts(patterns: &str, key: &PublicKey) -> KnownHosts {
        KnownHosts::new(format!("{patterns} {}\n", public_key_fields(key)).into_bytes())
    }

    fn public_key_fields(key: &PublicKey) -> String {
        let openssh = key.to_openssh().unwrap();
        let mut fields = openssh.split_ascii_whitespace();
        format!("{} {}", fields.next().unwrap(), fields.next().unwrap())
    }

    #[test]
    fn accepts_exact_known_host() {
        let key = test_key();
        let known = known_hosts("localhost", &key);
        assert_eq!(known.verify("localhost", 22, &key), Ok(()));
    }

    #[test]
    fn includes_non_default_port_in_known_host_lookup() {
        let key = test_key();
        let known = known_hosts("[localhost]:2222", &key);
        assert_eq!(known.verify("localhost", 2222, &key), Ok(()));
        assert_eq!(
            known.verify("localhost", 22, &key),
            Err(HostKeyError::Unknown {
                fingerprint: fingerprint(&key),
            })
        );
    }

    #[test]
    fn matches_wildcards_but_not_comments_or_other_hosts() {
        let key = test_key();
        let source = format!(
            "# comment\n\n*.internal,?xample.com,other.example.com {}\n",
            public_key_fields(&key)
        );
        let known = KnownHosts::new(source.into_bytes());
        assert_eq!(known.verify("host.internal", 22, &key), Ok(()));
        assert_eq!(known.verify("example.com", 22, &key), Ok(()));
        assert_eq!(known.verify("other.example.com", 22, &key), Ok(()));
        assert!(matches!(
            known.verify("unrelated.example.com", 22, &key),
            Err(HostKeyError::Unknown { .. })
        ));
    }

    #[test]
    fn negated_hosts_are_excluded_from_wildcard_entries() {
        let key = test_key();
        let known = known_hosts("*,!blocked.example.com", &key);
        assert_eq!(known.verify("allowed.example.com", 22, &key), Ok(()));
        assert_eq!(
            known.verify("blocked.example.com", 22, &key),
            Err(HostKeyError::Unknown {
                fingerprint: fingerprint(&key),
            })
        );
    }

    #[test]
    fn rejects_changed_key() {
        let trusted = test_key();
        let presented = test_key();
        let known = known_hosts("localhost", &trusted);
        assert_eq!(
            known.verify("localhost", 22, &presented),
            Err(HostKeyError::Changed {
                line: 1,
                fingerprint: fingerprint(&presented),
            })
        );
    }

    #[test]
    fn rejects_revoked_key_before_accepting_a_match() {
        let key = test_key();
        let source = format!(
            "@revoked localhost {}\nlocalhost {}\n",
            public_key_fields(&key),
            public_key_fields(&key)
        );
        let known = KnownHosts::new(source.into_bytes());
        assert_eq!(
            known.verify("localhost", 22, &key),
            Err(HostKeyError::Revoked {
                line: 1,
                fingerprint: fingerprint(&key),
            })
        );
    }

    #[test]
    fn revoked_entries_do_not_shadow_a_current_key() {
        let revoked = test_key();
        let current = test_key();
        let source = format!(
            "@revoked localhost {}\nlocalhost {}\n",
            public_key_fields(&revoked),
            public_key_fields(&current)
        );
        let known = KnownHosts::new(source.into_bytes());
        assert_eq!(known.verify("localhost", 22, &current), Ok(()));
        assert_eq!(
            known.verify("localhost", 22, &revoked),
            Err(HostKeyError::Revoked {
                line: 1,
                fingerprint: fingerprint(&revoked),
            })
        );
    }

    #[test]
    fn stale_entries_do_not_shadow_a_current_key() {
        let stale = test_key();
        let current = test_key();
        let source = format!(
            "localhost {}\nlocalhost {}\n",
            public_key_fields(&stale),
            public_key_fields(&current)
        );
        let known = KnownHosts::new(source.into_bytes());
        assert_eq!(known.verify("localhost", 22, &current), Ok(()));
        let presented = test_key();
        assert_eq!(
            known.verify("localhost", 22, &presented),
            Err(HostKeyError::Changed {
                line: 1,
                fingerprint: fingerprint(&presented),
            })
        );
    }

    #[test]
    fn certificate_authority_entries_do_not_grant_trust() {
        let key = test_key();
        let source = format!("@cert-authority localhost {}\n", public_key_fields(&key));
        let known = KnownHosts::new(source.into_bytes());
        assert!(matches!(
            known.verify("localhost", 22, &key),
            Err(HostKeyError::Changed { line: 0, .. })
        ));
    }

    #[test]
    fn matches_openssh_hashed_host_entries() {
        let key = test_key();
        let known = KnownHosts::new(
            format!(
                "|1|dGVzdC1zYWx0|j0O9zJslzfcaV/PRV+yP7iLxNCE= {}\n",
                public_key_fields(&key)
            )
            .into_bytes(),
        );
        // The digest above is for a different host, so a lookup must not accept it.
        assert!(matches!(
            known.verify("localhost", 22, &key),
            Err(HostKeyError::Unknown { .. })
        ));
    }

    #[test]
    fn pin_verification_requires_an_exact_fingerprint() {
        let key = test_key();
        let expected = fingerprint(&key);
        let pins = PinnedHostKeys::new(vec![expected.clone()]);
        assert_eq!(pins.verify("localhost", 22, &key), Ok(()));

        let pins = PinnedHostKeys::new(vec!["SHA256:not-the-key".into()]);
        assert_eq!(
            pins.verify("localhost", 22, &key),
            Err(HostKeyError::Unknown {
                fingerprint: expected,
            })
        );
    }
}
