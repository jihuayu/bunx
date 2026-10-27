use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, AuthResult, Handle, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key};
use russh::{Disconnect, Error as RusshError};
use tokio::sync::{Mutex, oneshot};

use crate::config::{Auth, Config};
use crate::host_key::{HostKeyError, fingerprint, sign_algorithm_name, verifier};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub host_key_algorithm: String,
    pub host_key_sha256: String,
    pub cipher_client_to_server: String,
    pub cipher_server_to_client: String,
}

#[derive(Debug)]
pub enum ConnectError {
    Timeout,
    HostKey(HostKeyError),
    Protocol(String),
    Io(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("SSH connection timed out"),
            Self::HostKey(error) => error.fmt(f),
            Self::Protocol(message) => write!(f, "SSH protocol error: {message}"),
            Self::Io(message) => write!(f, "SSH connection error: {message}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl ConnectError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "ERR_SSH_CONNECT_TIMEOUT",
            Self::HostKey(error) => error.code(),
            Self::Protocol(_) => "ERR_SSH_PROTOCOL",
            Self::Io(_) => "ERR_SSH_CONNECT",
        }
    }

    pub fn phase(&self) -> &'static str {
        match self {
            Self::Timeout | Self::Io(_) | Self::Protocol(_) => "handshake",
            Self::HostKey(_) => "host-key",
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Timeout,
    Rejected,
    InvalidKey(String),
    Protocol(String),
    ConnectionLost,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("SSH authentication timed out"),
            Self::Rejected => f.write_str("SSH authentication was rejected"),
            Self::InvalidKey(message) => write!(f, "invalid SSH private key: {message}"),
            Self::Protocol(message) => write!(f, "SSH authentication error: {message}"),
            Self::ConnectionLost => f.write_str("SSH connection was lost during authentication"),
        }
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "ERR_SSH_AUTH_TIMEOUT",
            Self::Rejected | Self::InvalidKey(_) => "ERR_SSH_AUTH",
            Self::Protocol(_) => "ERR_SSH_PROTOCOL",
            Self::ConnectionLost => "ERR_SSH_CONNECTION_LOST",
        }
    }

    pub fn phase(&self) -> &'static str {
        "auth"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseResult {
    pub forced: bool,
}

#[derive(Debug)]
pub enum CloseError {
    Timeout,
    Protocol(String),
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("SSH close timed out"),
            Self::Protocol(message) => write!(f, "SSH close error: {message}"),
        }
    }
}

impl std::error::Error for CloseError {}

impl CloseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "ERR_SSH_TIMEOUT",
            Self::Protocol(_) => "ERR_SSH_PROTOCOL",
        }
    }

    pub fn phase(&self) -> &'static str {
        "close"
    }
}

struct CheckState {
    sender: Option<oneshot::Sender<Result<ConnectionInfo, HostKeyError>>>,
    hostname: String,
    port: u16,
    username: String,
    verifier: Box<dyn crate::host_key::HostKeyVerifier + Send + Sync>,
    negotiated: Option<(String, String)>,
}

struct ClientHandler {
    state: Arc<Mutex<CheckState>>,
}

#[derive(Debug)]
enum ClientError {
    HostKey(HostKeyError),
    Russh(RusshError),
}

impl From<RusshError> for ClientError {
    fn from(error: RusshError) -> Self {
        Self::Russh(error)
    }
}

impl Handler for ClientHandler {
    type Error = ClientError;

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut state = self.state.lock().await;
        state.negotiated = Some((names.key.to_string(), names.cipher.as_ref().to_string()));
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let mut state = self.state.lock().await;
        let key = server_public_key.public_key();
        let result = state
            .verifier
            .verify(&state.hostname, state.port, &key)
            .map(|()| {
                let (host_key_algorithm, cipher) = state
                    .negotiated
                    .clone()
                    .unwrap_or_else(|| (sign_algorithm_name(&key), "unknown".into()));
                ConnectionInfo {
                    hostname: state.hostname.clone(),
                    port: state.port,
                    username: state.username.clone(),
                    host_key_algorithm,
                    host_key_sha256: fingerprint(&key),
                    cipher_client_to_server: cipher.clone(),
                    cipher_server_to_client: cipher,
                }
            });
        if let Some(sender) = state.sender.take() {
            let _ = sender.send(result.clone());
        }
        match result {
            Ok(_) => Ok(true),
            Err(error) => Err(ClientError::HostKey(error)),
        }
    }
}

struct SessionInner {
    /// Declared before `runtime` so the handle is dropped first; the reactor
    /// must outlive the driver task the handle joins on.
    handle: Mutex<Option<Handle<ClientHandler>>>,
    info: ConnectionInfo,
    /// Keeps the russh driver task's Tokio reactor alive for the session.
    _runtime: Option<Arc<tokio::runtime::Runtime>>,
}

/// An authenticated SSH transport.
///
/// Cloning a session shares one transport. Closing any clone closes the
/// transport for all of them; concurrent and repeated closes are idempotent.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

impl Session {
    pub fn info(&self) -> &ConnectionInfo {
        &self.inner.info
    }

    pub fn is_closed(&self) -> bool {
        self.inner
            .handle
            .try_lock()
            .map_or(false, |handle| handle.is_none())
    }

    pub async fn close(&self) -> Result<CloseResult, CloseError> {
        self.close_with_timeout(Duration::from_secs(5)).await
    }

    pub async fn close_with_timeout(
        &self,
        grace_period: Duration,
    ) -> Result<CloseResult, CloseError> {
        let mut slot = self.inner.handle.lock().await;
        let Some(mut handle) = slot.take() else {
            return Ok(CloseResult { forced: false });
        };

        match tokio::time::timeout(
            grace_period,
            handle.disconnect(Disconnect::ByApplication, "", ""),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) if handle.is_closed() => {
                let _ = error;
                return Ok(CloseResult { forced: false });
            }
            Ok(Err(error)) => return Err(CloseError::Protocol(error.to_string())),
            Err(_) => return Ok(CloseResult { forced: true }),
        }

        match tokio::time::timeout(grace_period, &mut handle).await {
            Ok(Ok(())) => Ok(CloseResult { forced: false }),
            Ok(Err(_)) => {
                // The transport is gone, which is the postcondition of close.
                Ok(CloseResult { forced: false })
            }
            Err(_) => Ok(CloseResult { forced: true }),
        }
    }
}

pub async fn connect(config: &Config) -> Result<Session, ConnectError> {
    connect_inner(config, None).await
}

/// Connect with a dedicated Tokio runtime retained by the returned session.
///
/// This is the entry point for the JavaScript bridge: russh's driver task and
/// later authentication/close calls must all run on the same live reactor.
pub async fn connect_with_runtime(
    config: &Config,
    runtime: Arc<tokio::runtime::Runtime>,
) -> Result<Session, ConnectError> {
    connect_inner(config, Some(runtime)).await
}

async fn connect_inner(
    config: &Config,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
) -> Result<Session, ConnectError> {
    let (sender, receiver) = oneshot::channel();
    let state = Arc::new(Mutex::new(CheckState {
        sender: Some(sender),
        hostname: config.hostname.clone(),
        port: config.port,
        username: config.username.clone(),
        verifier: verifier(&config.host_key),
        negotiated: None,
    }));
    let handler = ClientHandler {
        state: Arc::clone(&state),
    };
    let client_config = client::Config {
        channel_buffer_size: config.max_channels.min(100),
        nodelay: true,
        ..Default::default()
    };
    let client_config = Arc::new(client_config);
    let address = format!("{}:{}", config.hostname, config.port);

    let handle = tokio::time::timeout(
        Duration::from_millis(config.connect_timeout_ms),
        client::connect(client_config, address, handler),
    )
    .await
    .map_err(|_| ConnectError::Timeout)?
    .map_err(map_connect_error)?;

    let check = receiver.await.map_err(|_| {
        ConnectError::Protocol("connection closed before host key verification".into())
    })?;
    let info = match check {
        Ok(info) => info,
        Err(error) => {
            drop(handle);
            return Err(ConnectError::HostKey(error));
        }
    };
    Ok(Session {
        inner: Arc::new(SessionInner {
            handle: Mutex::new(Some(handle)),
            info,
            _runtime: runtime,
        }),
    })
}

impl Session {
    pub async fn authenticate(&self, config: &Config) -> Result<(), AuthError> {
        let mut slot = self.inner.handle.lock().await;
        let handle = slot
            .as_mut()
            .ok_or_else(|| AuthError::Protocol("SSH session is closed".into()))?;
        let result = tokio::time::timeout(
            Duration::from_millis(config.authentication_timeout_ms),
            authenticate_inner(handle, config),
        )
        .await
        .map_err(|_| AuthError::Timeout)??;
        if result.success() {
            Ok(())
        } else {
            Err(AuthError::Rejected)
        }
    }
}

async fn authenticate_inner(
    handle: &mut Handle<ClientHandler>,
    config: &Config,
) -> Result<AuthResult, AuthError> {
    match &config.auth {
        Auth::Password(secret) => {
            let password = secret
                .as_utf8()
                .map_err(|message| AuthError::Protocol(message.to_string()))?;
            handle
                .authenticate_password(config.username.clone(), password.into_owned())
                .await
                .map_err(map_auth_error)
        }
        Auth::PrivateKey { key, passphrase } => {
            let key_text = std::str::from_utf8(key)
                .map_err(|_| AuthError::InvalidKey("key is not UTF-8".into()))?;
            let passphrase = passphrase
                .as_ref()
                .map(|secret| {
                    secret
                        .as_utf8()
                        .map(|value| value.into_owned())
                        .map_err(|message| AuthError::Protocol(message.to_string()))
                })
                .transpose()?;
            let key = decode_secret_key(key_text, passphrase.as_deref())
                .map_err(|error| AuthError::InvalidKey(error.to_string()))?;
            let hash_algorithm = handle
                .best_supported_rsa_hash()
                .await
                .map_err(map_auth_error)?
                .flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_algorithm);
            handle
                .authenticate_publickey(config.username.clone(), key)
                .await
                .map_err(map_auth_error)
        }
    }
}

fn map_connect_error(error: ClientError) -> ConnectError {
    match error {
        ClientError::HostKey(error) => ConnectError::HostKey(error),
        ClientError::Russh(error) => map_russh_connect_error(error),
    }
}

fn map_russh_connect_error(error: RusshError) -> ConnectError {
    match error {
        RusshError::IO(error) => ConnectError::Io(error.to_string()),
        RusshError::Disconnect => ConnectError::Protocol("server disconnected".into()),
        other => ConnectError::Protocol(other.to_string()),
    }
}

fn map_auth_error(error: RusshError) -> AuthError {
    match error {
        RusshError::IO(_) | RusshError::Disconnect => AuthError::ConnectionLost,
        other => AuthError::Protocol(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rand::rng;
    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{self, Auth as ServerAuth, Server as _};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::config::{Auth, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_PENDING_OPERATIONS};
    use crate::host_key::fingerprint;

    const USERNAME: &str = "test-user";
    const PASSWORD: &str = "correct horse battery staple";

    struct TestServer {
        attempts: Arc<AtomicUsize>,
    }

    impl server::Server for TestServer {
        type Handler = TestHandler;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            TestHandler {
                attempts: Arc::clone(&self.attempts),
            }
        }
    }

    struct TestHandler {
        attempts: Arc<AtomicUsize>,
    }

    impl server::Handler for TestHandler {
        type Error = RusshError;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<ServerAuth, Self::Error> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(if user == USERNAME && password == PASSWORD {
                ServerAuth::Accept
            } else {
                ServerAuth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            _key: server::VerifiedPublicKey<'_>,
        ) -> Result<ServerAuth, Self::Error> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(if user == USERNAME {
                ServerAuth::Accept
            } else {
                ServerAuth::reject()
            })
        }
    }

    struct RunningServer {
        address: std::net::SocketAddr,
        host_key: russh::keys::PublicKey,
        attempts: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for RunningServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn start_server() -> RunningServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
        let host_public_key = host_key.public_key().clone();
        let mut config = server::Config {
            keys: vec![host_key],
            inactivity_timeout: None,
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        };
        config.methods = russh::MethodSet::empty();
        config.methods.push(russh::MethodKind::Password);
        config.methods.push(russh::MethodKind::PublicKey);
        let config = Arc::new(config);
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut server = TestServer {
            attempts: Arc::clone(&attempts),
        };
        let task = tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });
        RunningServer {
            address,
            host_key: host_public_key,
            attempts,
            task,
        }
    }

    fn config(server: &RunningServer, host_key: crate::HostKeyPolicy, auth: Auth) -> Config {
        Config::new(
            "127.0.0.1".to_string(),
            server.address.port(),
            USERNAME.to_string(),
            host_key,
            auth,
            5_000,
            5_000,
            DEFAULT_MAX_CHANNELS,
            DEFAULT_MAX_PENDING_OPERATIONS,
            5_000,
        )
        .unwrap()
    }

    fn known_hosts(server: &RunningServer) -> crate::HostKeyPolicy {
        use crate::config::KnownHostsSource;

        let openssh = server.host_key.to_openssh().unwrap();
        let key = openssh
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        crate::HostKeyPolicy::KnownHosts(KnownHostsSource::new(
            format!("[127.0.0.1]:{} {key}\n", server.address.port()).into_bytes(),
        ))
    }

    fn password_auth() -> Auth {
        Auth::Password(crate::Secret::Text(PASSWORD.to_string()))
    }

    #[tokio::test]
    async fn connects_and_authenticates_with_password() {
        let server = start_server().await;
        let session = connect(&config(&server, known_hosts(&server), password_auth()))
            .await
            .unwrap();
        assert_eq!(session.info().hostname, "127.0.0.1");
        assert_eq!(session.info().port, server.address.port());
        assert_eq!(session.info().username, USERNAME);
        assert_eq!(
            session.info().host_key_sha256,
            fingerprint(&server.host_key)
        );
        assert_eq!(
            session.info().host_key_algorithm,
            server.host_key.algorithm().to_string()
        );
        assert_ne!(session.info().cipher_client_to_server, "unknown");
        assert_eq!(
            session.info().cipher_client_to_server,
            session.info().cipher_server_to_client
        );
        session
            .authenticate(&config(&server, known_hosts(&server), password_auth()))
            .await
            .unwrap();
        assert_eq!(server.attempts.load(Ordering::SeqCst), 1);
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_with_private_key() {
        let server = start_server().await;
        let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
        let key = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes()
            .to_vec();
        let config = config(
            &server,
            known_hosts(&server),
            Auth::PrivateKey {
                key,
                passphrase: None,
            },
        );
        let session = connect(&config).await.unwrap();
        session.authenticate(&config).await.unwrap();
        assert_eq!(server.attempts.load(Ordering::SeqCst), 1);
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn pinned_fingerprint_accepts_and_rejects() {
        let server = start_server().await;
        let correct = crate::HostKeyPolicy::Pinned(vec![fingerprint(&server.host_key)]);
        let session = connect(&config(&server, correct, password_auth()))
            .await
            .unwrap();
        session.close().await.unwrap();

        let wrong = crate::HostKeyPolicy::Pinned(vec!["SHA256:wrong".into()]);
        let error = match connect(&config(&server, wrong, password_auth())).await {
            Ok(session) => {
                session.close().await.unwrap();
                panic!("wrong host key pin was accepted");
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConnectError::HostKey(HostKeyError::Unknown { .. })
        ));
    }

    #[tokio::test]
    async fn untrusted_and_changed_host_keys_never_authenticate() {
        let server = start_server().await;
        let other = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
        let other_public = other.public_key().to_openssh().unwrap();
        let unknown = crate::HostKeyPolicy::KnownHosts(crate::config::KnownHostsSource::new(
            format!("other-host {other_public}\n").into_bytes(),
        ));
        let error = match connect(&config(&server, unknown, password_auth())).await {
            Ok(session) => {
                session.close().await.unwrap();
                panic!("unknown host key was accepted");
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConnectError::HostKey(HostKeyError::Unknown { .. })
        ));
        assert_eq!(server.attempts.load(Ordering::SeqCst), 0);

        let changed = crate::HostKeyPolicy::KnownHosts(crate::config::KnownHostsSource::new(
            format!("[127.0.0.1]:{} {other_public}\n", server.address.port()).into_bytes(),
        ));
        let error = match connect(&config(&server, changed, password_auth())).await {
            Ok(session) => {
                session.close().await.unwrap();
                panic!("changed host key was accepted");
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConnectError::HostKey(HostKeyError::Changed { .. })
        ));
        assert_eq!(server.attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authentication_rejection_is_reported() {
        let server = start_server().await;
        let auth = Auth::Password(crate::Secret::Text("wrong".into()));
        let session = connect(&config(&server, known_hosts(&server), auth.clone()))
            .await
            .unwrap();
        assert!(matches!(
            session
                .authenticate(&config(&server, known_hosts(&server), auth))
                .await,
            Err(AuthError::Rejected)
        ));
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_is_shared_and_idempotent() {
        let server = start_server().await;
        let config = config(&server, known_hosts(&server), password_auth());
        let session = connect(&config).await.unwrap();
        session.authenticate(&config).await.unwrap();

        let clone = session.clone();
        let (first, second) = tokio::join!(session.close(), clone.close());
        assert!(first.is_ok());
        assert!(second.is_ok());

        let result = session.close().await.unwrap();
        assert!(!result.forced);
        assert!(session.is_closed());
    }
}
