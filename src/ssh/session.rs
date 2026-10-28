use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::client::{self, AuthResult, Handle, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key};
use russh::{ChannelMsg, Disconnect, Error as RusshError, Sig};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::{Mutex, oneshot, watch};

use crate::config::{Auth, Config, TransportConfig};
use crate::host_key::{HostKeyError, fingerprint, sign_algorithm_name, verifier};
use crate::process::{BlockingProcess, ProcessConfig, start_driver};

const MAX_INITIAL_CHANNEL_MESSAGES: usize = 256;
const MAX_INITIAL_CHANNEL_BYTES: usize = 256 * 1024;

pub type ExecCancelSender = watch::Sender<bool>;
pub type ExecCancelReceiver = watch::Receiver<bool>;

pub fn exec_cancellation() -> (ExecCancelSender, ExecCancelReceiver) {
    watch::channel(false)
}

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
    Timeout(&'static str),
    HostKey(HostKeyError),
    Protocol(String),
    Io(&'static str, String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout("dns") => f.write_str("SSH DNS lookup timed out"),
            Self::Timeout("tcp") => f.write_str("SSH TCP connection timed out"),
            Self::Timeout(_) => f.write_str("SSH handshake timed out"),
            Self::HostKey(error) => error.fmt(f),
            Self::Protocol(message) => write!(f, "SSH protocol error: {message}"),
            Self::Io("dns", message) => write!(f, "SSH DNS lookup failed: {message}"),
            Self::Io("tcp", message) => write!(f, "SSH TCP connection failed: {message}"),
            Self::Io(_, message) => write!(f, "SSH connection error: {message}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl ConnectError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "ERR_SSH_CONNECT_TIMEOUT",
            Self::HostKey(error) => error.code(),
            Self::Protocol(_) => "ERR_SSH_PROTOCOL",
            Self::Io(_, _) => "ERR_SSH_CONNECT",
        }
    }

    pub fn phase(&self) -> &'static str {
        match self {
            Self::Timeout(phase) | Self::Io(phase, _) => phase,
            Self::Protocol(_) => "handshake",
            Self::HostKey(_) => "host-key",
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Timeout,
    Aborted,
    Rejected,
    InvalidKey(String),
    Protocol(String),
    ConnectionLost,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("SSH authentication timed out"),
            Self::Aborted => f.write_str("SSH authentication was aborted"),
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
            Self::Aborted => "ERR_SSH_ABORTED",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteExecution {
    NotStarted,
    MayHaveStarted,
    ExitObserved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Exit { code: u32 },
    Signal { signal: String, core_dumped: bool },
    Unknown,
}

#[derive(Debug)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: ExitStatus,
    pub remote_execution: RemoteExecution,
}

#[derive(Debug)]
pub struct ExecError {
    code: &'static str,
    phase: &'static str,
    message: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: ExitStatus,
    pub remote_execution: RemoteExecution,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExecError {}

impl ExecError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn phase(&self) -> &'static str {
        self.phase
    }

    pub fn channel_closed(message: String) -> Self {
        exec_channel_error(message)
    }

    pub(crate) fn new(
        code: &'static str,
        phase: &'static str,
        message: impl Into<String>,
        remote_execution: RemoteExecution,
    ) -> Self {
        Self {
            code,
            phase,
            message: message.into(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: ExitStatus::Unknown,
            remote_execution,
        }
    }
}

struct PartialExec {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    total_output: u64,
    exit_status: ExitStatus,
    remote_execution: RemoteExecution,
}

impl PartialExec {
    fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            total_output: 0,
            exit_status: ExitStatus::Unknown,
            remote_execution: RemoteExecution::NotStarted,
        }
    }

    fn sent() -> Self {
        Self {
            remote_execution: RemoteExecution::MayHaveStarted,
            ..Self::new()
        }
    }

    fn push(&mut self, stderr: bool, data: &[u8], max_output_bytes: u64) -> bool {
        let Ok(data_len) = u64::try_from(data.len()) else {
            return false;
        };
        let Some(total) = self.total_output.checked_add(data_len) else {
            return false;
        };
        if total > max_output_bytes {
            return false;
        }
        let target = if stderr {
            &mut self.stderr
        } else {
            &mut self.stdout
        };
        target.extend_from_slice(data);
        self.total_output = total;
        true
    }

    fn remote_execution(&self) -> RemoteExecution {
        if !matches!(self.exit_status, ExitStatus::Unknown) {
            RemoteExecution::ExitObserved
        } else if self.remote_execution == RemoteExecution::NotStarted {
            RemoteExecution::NotStarted
        } else {
            RemoteExecution::MayHaveStarted
        }
    }
}

#[derive(Debug)]
enum ExecReply {
    Accepted,
    Rejected,
}

struct ReadTaskResult {
    output: PartialExec,
    clean_close: bool,
    output_limit: bool,
}

#[derive(Clone, Copy)]
enum ExecStop {
    Timeout,
    Cancelled,
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

/// A session together with the runtime that drives its russh task.
///
/// The synchronous methods are for native callers that already run off the
/// JavaScript thread. Every operation uses the same runtime as the initial
/// handshake.
#[derive(Clone)]
pub struct BlockingSession {
    runtime: Arc<tokio::runtime::Runtime>,
    session: Arc<std::sync::Mutex<Session>>,
}

impl BlockingSession {
    pub fn connect_transport(config: &TransportConfig) -> Result<Self, ConnectError> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("bun-ssh")
                .build()
                .map_err(|error| ConnectError::Io("handshake", error.to_string()))?,
        );
        let session =
            runtime.block_on(connect_transport_with_runtime(config, Arc::clone(&runtime)))?;
        Ok(Self {
            runtime,
            session: Arc::new(std::sync::Mutex::new(session)),
        })
    }

    pub fn info(&self) -> ConnectionInfo {
        self.session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .info()
            .clone()
    }

    pub fn is_closed(&self) -> bool {
        self.session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_closed()
    }

    pub fn authenticate_with(
        &self,
        auth: &Auth,
        username: &str,
        authentication_timeout_ms: u64,
    ) -> Result<(), AuthError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.runtime
            .block_on(session.authenticate_with(auth, username, authentication_timeout_ms))
    }

    pub fn authenticate_with_cancel(
        &self,
        auth: &Auth,
        username: &str,
        authentication_timeout_ms: u64,
        cancel: watch::Receiver<bool>,
    ) -> Result<(), AuthError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.runtime.block_on(session.authenticate_with_cancel(
            auth,
            username,
            authentication_timeout_ms,
            cancel,
        ))
    }

    pub fn close_with_timeout(&self, grace_period: Duration) -> Result<CloseResult, CloseError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.runtime
            .block_on(session.close_with_timeout(grace_period))
    }

    pub fn exec_with_cancel(
        &self,
        command: Vec<u8>,
        stdin: Vec<u8>,
        timeout: Option<Duration>,
        max_output_bytes: u64,
        cancel: watch::Receiver<bool>,
    ) -> Result<ExecResult, ExecError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        self.runtime.block_on(session.exec_with_cancel(
            command,
            stdin,
            timeout,
            max_output_bytes,
            cancel,
        ))
    }

    pub fn start_process(
        &self,
        command: Vec<u8>,
        config: ProcessConfig,
        timeout: Option<Duration>,
        cancel: watch::Receiver<bool>,
    ) -> Result<BlockingProcess, ExecError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let runtime = Arc::clone(&self.runtime);
        self.runtime
            .block_on(session.start_process_with_cancel(command, config, timeout, cancel, runtime))
    }
}

impl Session {
    pub fn info(&self) -> &ConnectionInfo {
        &self.inner.info
    }

    pub fn is_closed(&self) -> bool {
        self.inner.handle.try_lock().map_or(false, |handle| {
            handle.as_ref().map_or(true, |handle| handle.is_closed())
        })
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
        let started = tokio::time::Instant::now();

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

        let remaining = grace_period.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, &mut handle).await {
            Ok(Ok(())) => Ok(CloseResult { forced: false }),
            Ok(Err(_)) => {
                // The transport is gone, which is the postcondition of close.
                Ok(CloseResult { forced: false })
            }
            Err(_) => Ok(CloseResult { forced: true }),
        }
    }

    pub async fn exec_with_cancel(
        &self,
        command: Vec<u8>,
        stdin: Vec<u8>,
        timeout: Option<Duration>,
        max_output_bytes: u64,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<ExecResult, ExecError> {
        if *cancel.borrow() {
            return Err(ExecError {
                code: "ERR_SSH_ABORTED",
                phase: "exec",
                message: "SSH execution was aborted".into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: ExitStatus::Unknown,
                remote_execution: RemoteExecution::NotStarted,
            });
        }

        let deadline = timeout.and_then(|timeout| tokio::time::Instant::now().checked_add(timeout));
        if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            return Err(ExecError {
                code: "ERR_SSH_TIMEOUT",
                phase: "exec",
                message: "SSH execution timed out".into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: ExitStatus::Unknown,
                remote_execution: RemoteExecution::NotStarted,
            });
        }

        let channel = {
            let handle = self.inner.handle.lock().await;
            let handle = handle
                .as_ref()
                .ok_or_else(|| exec_channel_error("SSH session is closed"))?;
            tokio::select! {
                result = handle.channel_open_session() => {
                    result.map_err(|error| exec_channel_error(error.to_string()))?
                }
                stop = wait_for_exec_stop(&mut cancel, deadline) => {
                    return Err(exec_stop_error(stop, PartialExec::new()));
                }
            }
        };

        let exec_result = tokio::select! {
            result = channel.exec(true, command) => result,
            stop = wait_for_exec_stop(&mut cancel, deadline) => {
                let _ = tokio::time::timeout(Duration::from_millis(250), channel.close()).await;
                return Err(exec_stop_error(stop, PartialExec::sent()));
            }
        };
        if let Err(error) = exec_result {
            let _ = channel.close().await;
            return Err(ExecError {
                code: "ERR_SSH_IO",
                phase: "exec",
                message: format!("failed to send SSH exec request: {error}"),
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: ExitStatus::Unknown,
                remote_execution: RemoteExecution::MayHaveStarted,
            });
        }

        let (mut read_half, write_half) = channel.split();
        let (reply_sender, reply_receiver) = oneshot::channel();
        let (done_sender, mut done_receiver) = watch::channel(false);
        let mut reader = tokio::spawn(async move {
            let output = read_exec_output(&mut read_half, max_output_bytes, reply_sender).await;
            let _ = done_sender.send(true);
            output
        });

        let reply = tokio::select! {
            biased;
            reply = reply_receiver => reply,
            stop = wait_for_exec_stop(&mut cancel, deadline) => {
                reader.abort();
                close_exec_channel(&write_half).await;
                return Err(exec_stop_error(stop, PartialExec::sent()));
            }
            _ = done_receiver.changed() => {
                let output = finish_exec_reader(&mut reader).await;
                close_exec_channel(&write_half).await;
                return Err(exec_error_from_reader(
                    "ERR_SSH_PROTOCOL",
                    "exec",
                    "SSH exec channel closed before acknowledging the request",
                    output,
                ));
            }
        };

        match reply {
            Ok(ExecReply::Accepted) => {}
            Ok(ExecReply::Rejected) => {
                reader.abort();
                close_exec_channel(&write_half).await;
                return Err(ExecError {
                    code: "ERR_SSH_EXEC_REJECTED",
                    phase: "exec",
                    message: "SSH server rejected the exec request".into(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_status: ExitStatus::Unknown,
                    remote_execution: RemoteExecution::NotStarted,
                });
            }
            Err(_) => {
                let output = finish_exec_reader(&mut reader).await;
                close_exec_channel(&write_half).await;
                return Err(exec_error_from_reader(
                    "ERR_SSH_PROTOCOL",
                    "exec",
                    "SSH exec request ended without a reply",
                    output,
                ));
            }
        }

        if !stdin.is_empty() {
            let write_result = tokio::select! {
                result = write_half.data_bytes(stdin) => Some(result),
                stop = wait_for_exec_stop(&mut cancel, deadline) => {
                    reader.abort();
                    close_exec_channel(&write_half).await;
                    return Err(exec_stop_error(stop, PartialExec::sent()));
                }
                _ = done_receiver.changed() => None,
            };
            if let Some(Err(error)) = write_result {
                reader.abort();
                let output = finish_exec_reader(&mut reader).await;
                close_exec_channel(&write_half).await;
                return Err(exec_error_from_reader(
                    "ERR_SSH_IO",
                    "exec",
                    format!("failed to write SSH stdin: {error}"),
                    output,
                ));
            }
        }

        if !*done_receiver.borrow() {
            let eof_result = tokio::select! {
                result = write_half.eof() => Some(result),
                stop = wait_for_exec_stop(&mut cancel, deadline) => {
                    reader.abort();
                    close_exec_channel(&write_half).await;
                    return Err(exec_stop_error(stop, PartialExec::sent()));
                }
                _ = done_receiver.changed() => None,
            };
            if let Some(Err(error)) = eof_result {
                reader.abort();
                let output = finish_exec_reader(&mut reader).await;
                close_exec_channel(&write_half).await;
                return Err(exec_error_from_reader(
                    "ERR_SSH_IO",
                    "exec",
                    format!("failed to close SSH stdin: {error}"),
                    output,
                ));
            }
        }

        let output = tokio::select! {
            result = &mut reader => match result {
                Ok(output) => output,
                Err(error) => {
                    close_exec_channel(&write_half).await;
                    return Err(ExecError {
                        code: "ERR_SSH_PROTOCOL",
                        phase: "exec",
                        message: format!("SSH exec reader failed: {error}"),
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        exit_status: ExitStatus::Unknown,
                        remote_execution: RemoteExecution::MayHaveStarted,
                    });
                }
            },
            stop = wait_for_exec_stop(&mut cancel, deadline) => {
                reader.abort();
                close_exec_channel(&write_half).await;
                return Err(exec_stop_error(stop, PartialExec::sent()));
            }
        };

        close_exec_channel(&write_half).await;

        if output.output_limit {
            return Err(exec_error_from_reader(
                "ERR_SSH_OUTPUT_LIMIT",
                "exec",
                format!("SSH command output exceeded the {max_output_bytes}-byte limit"),
                output,
            ));
        }
        if !output.clean_close {
            return Err(exec_error_from_reader(
                "ERR_SSH_CONNECTION_LOST",
                "io",
                "SSH connection was lost before the exec channel closed cleanly",
                output,
            ));
        }

        let remote_execution = output.output.remote_execution();
        Ok(ExecResult {
            stdout: output.output.stdout,
            stderr: output.output.stderr,
            exit_status: output.output.exit_status,
            remote_execution,
        })
    }

    async fn start_process_with_cancel(
        &self,
        command: Vec<u8>,
        config: ProcessConfig,
        timeout: Option<Duration>,
        mut cancel: watch::Receiver<bool>,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Result<BlockingProcess, ExecError> {
        if *cancel.borrow() {
            return Err(ExecError::new(
                "ERR_SSH_ABORTED",
                "exec",
                "SSH process was aborted",
                RemoteExecution::NotStarted,
            ));
        }

        let deadline = timeout.and_then(|timeout| tokio::time::Instant::now().checked_add(timeout));
        if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            return Err(ExecError::new(
                "ERR_SSH_TIMEOUT",
                "exec",
                "SSH process timed out",
                RemoteExecution::NotStarted,
            ));
        }

        let mut channel = {
            let handle = self.inner.handle.lock().await;
            let handle = handle
                .as_ref()
                .ok_or_else(|| exec_channel_error("SSH session is closed"))?;
            tokio::select! {
                result = handle.channel_open_session() => {
                    result.map_err(|error| ExecError::new(
                        "ERR_SSH_CHANNEL_OPEN",
                        "channel",
                        format!("failed to open SSH channel: {error}"),
                        RemoteExecution::NotStarted,
                    ))?
                }
                stop = wait_for_exec_stop(&mut cancel, deadline) => {
                    return Err(exec_stop_error(stop, PartialExec::new()));
                }
            }
        };

        tokio::select! {
            result = channel.exec(true, command) => {
                if let Err(error) = result {
                    let _ = channel.close().await;
                    return Err(ExecError::new(
                        "ERR_SSH_IO",
                        "exec",
                        format!("failed to send SSH exec request: {error}"),
                        RemoteExecution::MayHaveStarted,
                    ));
                }
            }
            stop = wait_for_exec_stop(&mut cancel, deadline) => {
                let _ = channel.close().await;
                return Err(exec_stop_error(stop, PartialExec::sent()));
            }
        }

        let mut initial_messages = Vec::new();
        let mut initial_bytes = 0usize;
        loop {
            let message = tokio::select! {
                message = channel.wait() => message,
                stop = wait_for_exec_stop(&mut cancel, deadline) => {
                    let _ = channel.close().await;
                    return Err(ExecError::new(
                        match stop {
                            ExecStop::Timeout => "ERR_SSH_TIMEOUT",
                            ExecStop::Cancelled => "ERR_SSH_ABORTED",
                        },
                        "exec",
                        match stop {
                            ExecStop::Timeout => "SSH process timed out",
                            ExecStop::Cancelled => "SSH process was aborted",
                        },
                        RemoteExecution::MayHaveStarted,
                    ));
                }
            };

            match message {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    let _ = channel.close().await;
                    return Err(ExecError::new(
                        "ERR_SSH_EXEC_REJECTED",
                        "exec",
                        "SSH server rejected the exec request",
                        RemoteExecution::NotStarted,
                    ));
                }
                Some(ChannelMsg::Close | ChannelMsg::Eof) | None => {
                    let _ = channel.close().await;
                    return Err(ExecError::new(
                        "ERR_SSH_PROTOCOL",
                        "exec",
                        "SSH exec request ended without a reply",
                        RemoteExecution::MayHaveStarted,
                    ));
                }
                Some(message) => {
                    let message_bytes = match &message {
                        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                            data.len()
                        }
                        _ => 0,
                    };
                    initial_bytes = initial_bytes.saturating_add(message_bytes);
                    if initial_messages.len() >= MAX_INITIAL_CHANNEL_MESSAGES
                        || initial_bytes > MAX_INITIAL_CHANNEL_BYTES
                    {
                        let _ = channel.close().await;
                        return Err(ExecError::new(
                            "ERR_SSH_RESOURCE_LIMIT",
                            "exec",
                            "SSH server sent too much data before accepting the exec request",
                            RemoteExecution::MayHaveStarted,
                        ));
                    }
                    initial_messages.push(message);
                }
            }
        }

        let process = start_driver(channel, runtime, config, cancel, initial_messages);
        Ok(process)
    }
}

async fn read_exec_output(
    read_half: &mut russh::ChannelReadHalf,
    max_output_bytes: u64,
    reply: oneshot::Sender<ExecReply>,
) -> ReadTaskResult {
    let mut output = PartialExec::sent();
    let mut reply = Some(reply);
    let mut clean_close = false;
    let mut output_limit = false;

    while let Some(message) = read_half.wait().await {
        match message {
            ChannelMsg::Success => {
                output.remote_execution = RemoteExecution::MayHaveStarted;
                if let Some(reply) = reply.take() {
                    let _ = reply.send(ExecReply::Accepted);
                }
            }
            ChannelMsg::Failure => {
                output.remote_execution = RemoteExecution::NotStarted;
                if let Some(reply) = reply.take() {
                    let _ = reply.send(ExecReply::Rejected);
                }
            }
            ChannelMsg::Data { data } => {
                output.remote_execution = RemoteExecution::MayHaveStarted;
                if !output.push(false, &data, max_output_bytes) {
                    output_limit = true;
                    if let Some(reply) = reply.take() {
                        let _ = reply.send(ExecReply::Accepted);
                    }
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, ext } if ext == 1 => {
                output.remote_execution = RemoteExecution::MayHaveStarted;
                if !output.push(true, &data, max_output_bytes) {
                    output_limit = true;
                    if let Some(reply) = reply.take() {
                        let _ = reply.send(ExecReply::Accepted);
                    }
                    break;
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                if matches!(output.exit_status, ExitStatus::Unknown) {
                    output.exit_status = ExitStatus::Exit { code: exit_status };
                }
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                ..
            } => {
                if matches!(output.exit_status, ExitStatus::Unknown) {
                    output.exit_status = ExitStatus::Signal {
                        signal: signal_name_name(&signal_name),
                        core_dumped,
                    };
                }
            }
            ChannelMsg::Close => {
                clean_close = true;
                break;
            }
            ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. } => {}
            _ => {}
        }
    }

    ReadTaskResult {
        output,
        clean_close,
        output_limit,
    }
}

async fn wait_for_exec_stop(
    cancel: &mut watch::Receiver<bool>,
    deadline: Option<tokio::time::Instant>,
) -> ExecStop {
    if *cancel.borrow() {
        return ExecStop::Cancelled;
    }
    if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
        return ExecStop::Timeout;
    }
    tokio::select! {
        result = cancel.changed() => {
            let _ = result;
            ExecStop::Cancelled
        }
        _ = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        } => ExecStop::Timeout,
    }
}

async fn finish_exec_reader(
    reader: &mut tokio::task::JoinHandle<ReadTaskResult>,
) -> ReadTaskResult {
    match tokio::time::timeout(Duration::from_millis(500), reader).await {
        Ok(Ok(output)) => output,
        _ => ReadTaskResult {
            output: PartialExec::sent(),
            clean_close: false,
            output_limit: false,
        },
    }
}

async fn close_exec_channel(write_half: &russh::ChannelWriteHalf<Msg>) {
    let _ = tokio::time::timeout(Duration::from_millis(250), write_half.close()).await;
}

fn exec_channel_error(message: impl Into<String>) -> ExecError {
    ExecError {
        code: "ERR_SSH_CHANNEL_OPEN",
        phase: "channel",
        message: message.into(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_status: ExitStatus::Unknown,
        remote_execution: RemoteExecution::NotStarted,
    }
}

fn exec_stop_error(stop: ExecStop, output: PartialExec) -> ExecError {
    let (code, phase, message) = match stop {
        ExecStop::Timeout => (
            "ERR_SSH_TIMEOUT",
            "exec",
            "SSH execution timed out".to_string(),
        ),
        ExecStop::Cancelled => (
            "ERR_SSH_ABORTED",
            "exec",
            "SSH execution was aborted".to_string(),
        ),
    };
    exec_error_from_reader(
        code,
        phase,
        message,
        ReadTaskResult {
            output,
            clean_close: false,
            output_limit: false,
        },
    )
}

fn exec_error_from_reader(
    code: &'static str,
    phase: &'static str,
    message: impl Into<String>,
    result: ReadTaskResult,
) -> ExecError {
    ExecError {
        code,
        phase,
        message: message.into(),
        remote_execution: result.output.remote_execution(),
        stdout: result.output.stdout,
        stderr: result.output.stderr,
        exit_status: result.output.exit_status,
    }
}

fn signal_name_name(signal: &Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(name) => name.clone(),
    }
}

pub async fn connect(config: &Config) -> Result<Session, ConnectError> {
    connect_transport(&config.transport()).await
}

/// Connect and verify the server host key without resolving or sending an
/// authentication secret.
pub async fn connect_transport(config: &TransportConfig) -> Result<Session, ConnectError> {
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
    connect_transport_with_runtime(&config.transport(), runtime).await
}

pub async fn connect_transport_with_runtime(
    config: &TransportConfig,
    runtime: Arc<tokio::runtime::Runtime>,
) -> Result<Session, ConnectError> {
    connect_inner(config, Some(runtime)).await
}

async fn connect_inner(
    config: &TransportConfig,
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
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.connect_timeout_ms);
    let addresses = tokio::time::timeout_at(
        deadline,
        lookup_host((config.hostname.as_str(), config.port)),
    )
    .await
    .map_err(|_| ConnectError::Timeout("dns"))?
    .map_err(|error| ConnectError::Io("dns", error.to_string()))?;
    let mut last_tcp_error = None;
    let mut socket = None;
    for address in addresses {
        match tokio::time::timeout_at(deadline, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                socket = Some(stream);
                break;
            }
            Ok(Err(error)) => last_tcp_error = Some(error),
            Err(_) => return Err(ConnectError::Timeout("tcp")),
        }
    }
    let socket = socket.ok_or_else(|| {
        ConnectError::Io(
            "tcp",
            last_tcp_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "hostname resolved to no addresses".into()),
        )
    })?;
    let _ = socket.set_nodelay(true);

    let handle = tokio::time::timeout_at(
        deadline,
        client::connect_stream(client_config, socket, handler),
    )
    .await
    .map_err(|_| ConnectError::Timeout("handshake"))?
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
        self.authenticate_with(
            &config.auth,
            config.username.as_str(),
            config.authentication_timeout_ms,
        )
        .await
    }

    pub async fn authenticate_with(
        &self,
        auth: &Auth,
        username: &str,
        authentication_timeout_ms: u64,
    ) -> Result<(), AuthError> {
        let mut slot = self.inner.handle.lock().await;
        let handle = slot
            .as_mut()
            .ok_or_else(|| AuthError::Protocol("SSH session is closed".into()))?;
        let result = tokio::time::timeout(
            Duration::from_millis(authentication_timeout_ms),
            authenticate_inner(handle, auth, username),
        )
        .await
        .map_err(|_| AuthError::Timeout)??;
        if result.success() {
            Ok(())
        } else {
            Err(AuthError::Rejected)
        }
    }

    pub async fn authenticate_with_cancel(
        &self,
        auth: &Auth,
        username: &str,
        authentication_timeout_ms: u64,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<(), AuthError> {
        if *cancel.borrow() {
            return Err(AuthError::Aborted);
        }
        let mut slot = self.inner.handle.lock().await;
        let handle = slot
            .as_mut()
            .ok_or_else(|| AuthError::Protocol("SSH session is closed".into()))?;
        tokio::select! {
            biased;
            _ = cancel.changed() => Err(AuthError::Aborted),
            result = tokio::time::timeout(
                Duration::from_millis(authentication_timeout_ms),
                authenticate_inner(handle, auth, username),
            ) => {
                let result = result.map_err(|_| AuthError::Timeout)??;
                if result.success() {
                    Ok(())
                } else {
                    Err(AuthError::Rejected)
                }
            }
        }
    }
}

async fn authenticate_inner(
    handle: &mut Handle<ClientHandler>,
    auth: &Auth,
    username: &str,
) -> Result<AuthResult, AuthError> {
    match auth {
        Auth::Password(secret) => {
            let password = secret
                .as_utf8()
                .map_err(|message| AuthError::Protocol(message.to_string()))?;
            handle
                .authenticate_password(username.to_string(), password.into_owned())
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
                .authenticate_publickey(username.to_string(), key)
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
        RusshError::IO(error) => ConnectError::Io("handshake", error.to_string()),
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
        channel_gate: Option<Arc<ChannelGate>>,
        auth_gate: Option<Arc<AuthGate>>,
        exec_gate: Option<Arc<ExecGate>>,
    }

    struct ChannelGate {
        opened: tokio::sync::Notify,
        release: tokio::sync::Notify,
        opens: AtomicUsize,
    }

    struct AuthGate {
        opened: tokio::sync::Notify,
        release: tokio::sync::Notify,
        entered: std::sync::atomic::AtomicBool,
    }

    struct ExecGate {
        opened: tokio::sync::Notify,
        release: tokio::sync::Notify,
        finished: tokio::sync::Notify,
        entered: std::sync::atomic::AtomicBool,
    }

    impl server::Server for TestServer {
        type Handler = TestHandler;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            TestHandler {
                attempts: Arc::clone(&self.attempts),
                channel_gate: self.channel_gate.clone(),
                auth_gate: self.auth_gate.clone(),
                exec_gate: self.exec_gate.clone(),
            }
        }
    }

    struct TestHandler {
        attempts: Arc<AtomicUsize>,
        channel_gate: Option<Arc<ChannelGate>>,
        auth_gate: Option<Arc<AuthGate>>,
        exec_gate: Option<Arc<ExecGate>>,
    }

    impl server::Handler for TestHandler {
        type Error = RusshError;

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if let Some(gate) = &self.channel_gate {
                if gate.opens.fetch_add(1, Ordering::SeqCst) == 0 {
                    gate.opened.notify_one();
                    gate.release.notified().await;
                }
            }
            reply.accept().await;
            Ok(())
        }

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<ServerAuth, Self::Error> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.auth_gate {
                if !gate.entered.swap(true, Ordering::SeqCst) {
                    gate.opened.notify_one();
                    gate.release.notified().await;
                }
            }
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

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if data == b"stalled-exec" {
                if let Some(gate) = &self.exec_gate {
                    if !gate.entered.swap(true, Ordering::SeqCst) {
                        gate.opened.notify_one();
                        gate.release.notified().await;
                    }
                    gate.finished.notify_one();
                }
                let _ = session.channel_success(channel);
                return Ok(());
            }
            session.channel_success(channel)?;
            match data {
                b"gated-ok" => {
                    session.data(channel, "ok")?;
                    session.exit_status_request(channel, 0)?;
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                b"no-status" => {
                    session.data(channel, "tail")?;
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                b"lost-before-status" => {
                    session.data(channel, "partial")?;
                    session.disconnect(Disconnect::ByApplication, "", "")?;
                }
                b"lost-before-ack" => {
                    session.disconnect(Disconnect::ByApplication, "", "")?;
                }
                b"signal-status" => {
                    session.exit_signal_request(channel, Sig::TERM, true, "", "")?;
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                _ => {
                    session.channel_failure(channel)?;
                }
            }
            Ok(())
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

    async fn start_server_with_gates(
        channel_gate: Option<Arc<ChannelGate>>,
        auth_gate: Option<Arc<AuthGate>>,
        exec_gate: Option<Arc<ExecGate>>,
    ) -> RunningServer {
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
            channel_gate: channel_gate.clone(),
            auth_gate: auth_gate.clone(),
            exec_gate,
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

    async fn start_server() -> RunningServer {
        start_server_with_gates(None, None, None).await
    }

    struct BlockingServer {
        address: std::net::SocketAddr,
        host_key: russh::keys::PublicKey,
        _runtime: tokio::runtime::Runtime,
    }

    fn start_blocking_server() -> BlockingServer {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let listener =
            runtime.block_on(async { TcpListener::bind(("127.0.0.1", 0)).await.unwrap() });
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
        let config = Arc::new(config);
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut server = TestServer {
            attempts,
            channel_gate: None,
            auth_gate: None,
            exec_gate: None,
        };
        runtime.spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });
        BlockingServer {
            address,
            host_key: host_public_key,
            _runtime: runtime,
        }
    }

    fn known_hosts_for(
        address: std::net::SocketAddr,
        host_key: &russh::keys::PublicKey,
    ) -> crate::HostKeyPolicy {
        use crate::config::KnownHostsSource;

        let openssh = host_key.to_openssh().unwrap();
        let key = openssh
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        crate::HostKeyPolicy::KnownHosts(KnownHostsSource::new(
            format!("[127.0.0.1]:{} {key}\n", address.port()).into_bytes(),
        ))
    }

    fn blocking_session(server: &BlockingServer) -> BlockingSession {
        let config = Config::new(
            "127.0.0.1".to_string(),
            server.address.port(),
            USERNAME.to_string(),
            known_hosts_for(server.address, &server.host_key),
            password_auth(),
            5_000,
            5_000,
            DEFAULT_MAX_CHANNELS,
            DEFAULT_MAX_PENDING_OPERATIONS,
            5_000,
        )
        .unwrap();
        let session = BlockingSession::connect_transport(&config.transport()).unwrap();
        session
            .authenticate_with(&config.auth, USERNAME, 5_000)
            .unwrap();
        session
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

    #[tokio::test]
    async fn exec_cancellation_interrupts_a_pending_channel_open() {
        let gate = Arc::new(ChannelGate {
            opened: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            opens: AtomicUsize::new(0),
        });
        let server = start_server_with_gates(Some(Arc::clone(&gate)), None, None).await;
        let config = config(&server, known_hosts(&server), password_auth());
        let session = connect(&config).await.unwrap();
        session.authenticate(&config).await.unwrap();

        let (cancel_sender, cancel) = exec_cancellation();
        let task_session = session.clone();
        let task = tokio::spawn(async move {
            task_session
                .exec_with_cancel(b"gated-ok".to_vec(), Vec::new(), None, 1024, cancel)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), gate.opened.notified())
            .await
            .expect("server did not receive the first channel open");
        cancel_sender.send_replace(true);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled channel open did not settle")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_ABORTED");
        assert_eq!(error.phase(), "exec");
        assert_eq!(error.remote_execution, RemoteExecution::NotStarted);

        gate.release.notify_one();
        let (_cancel_sender, cancel) = exec_cancellation();
        let result = session
            .exec_with_cancel(b"gated-ok".to_vec(), Vec::new(), None, 1024, cancel)
            .await
            .unwrap();
        assert_eq!(result.stdout, b"ok");
        assert_eq!(result.exit_status, ExitStatus::Exit { code: 0 });
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn exec_cancellation_interrupts_a_stalled_exec_request() {
        let gate = Arc::new(ExecGate {
            opened: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            finished: tokio::sync::Notify::new(),
            entered: std::sync::atomic::AtomicBool::new(false),
        });
        let server = start_server_with_gates(None, None, Some(Arc::clone(&gate))).await;
        let config = config(&server, known_hosts(&server), password_auth());
        let session = connect(&config).await.unwrap();
        session.authenticate(&config).await.unwrap();

        let (cancel_sender, cancel) = exec_cancellation();
        let task_session = session.clone();
        let task = tokio::spawn(async move {
            task_session
                .exec_with_cancel(b"stalled-exec".to_vec(), Vec::new(), None, 1024, cancel)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), gate.opened.notified())
            .await
            .expect("server did not receive the exec request");
        cancel_sender.send_replace(true);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled exec request did not settle")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_ABORTED");
        assert_eq!(error.phase(), "exec");
        assert_eq!(error.remote_execution, RemoteExecution::MayHaveStarted);

        gate.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), gate.finished.notified())
            .await
            .expect("stalled exec request did not finish");
        let (_cancel_sender, cancel) = exec_cancellation();
        let result = session
            .exec_with_cancel(b"gated-ok".to_vec(), Vec::new(), None, 1024, cancel)
            .await
            .unwrap();
        assert_eq!(result.stdout, b"ok");
        assert_eq!(result.exit_status, ExitStatus::Exit { code: 0 });
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn authentication_cancellation_interrupts_a_stalled_server() {
        let gate = Arc::new(AuthGate {
            opened: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            entered: std::sync::atomic::AtomicBool::new(false),
        });
        let server = start_server_with_gates(None, Some(Arc::clone(&gate)), None).await;
        let config = config(&server, known_hosts(&server), password_auth());
        let session = connect(&config).await.unwrap();

        let (cancel_sender, cancel) = exec_cancellation();
        let task_session = session.clone();
        let auth = password_auth();
        let task = tokio::spawn(async move {
            task_session
                .authenticate_with_cancel(&auth, USERNAME, 30_000, cancel)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), gate.opened.notified())
            .await
            .expect("server did not receive the authentication request");
        cancel_sender.send_replace(true);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled authentication did not settle")
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, AuthError::Aborted));

        gate.release.notify_one();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn exec_connection_loss_before_ack_is_may_have_started() {
        let server = start_server().await;
        let session = connect(&config(&server, known_hosts(&server), password_auth()))
            .await
            .unwrap();
        session
            .authenticate(&config(&server, known_hosts(&server), password_auth()))
            .await
            .unwrap();
        let (_cancel_sender, cancel) = exec_cancellation();

        let error = session
            .exec_with_cancel(b"lost-before-ack".to_vec(), Vec::new(), None, 1024, cancel)
            .await
            .unwrap_err();
        assert!(matches!(
            error.code(),
            "ERR_SSH_PROTOCOL" | "ERR_SSH_CONNECTION_LOST"
        ));
        assert_eq!(error.remote_execution, RemoteExecution::MayHaveStarted);
    }

    #[test]
    fn clean_channel_close_without_status_is_unknown_not_success() {
        let server = start_blocking_server();
        let session = blocking_session(&server);
        let (_cancel_sender, cancel) = exec_cancellation();

        let result = session
            .exec_with_cancel(b"no-status".to_vec(), Vec::new(), None, 1024, cancel)
            .unwrap();
        assert_eq!(result.stdout, b"tail");
        assert_eq!(result.exit_status, ExitStatus::Unknown);
        assert_eq!(result.remote_execution, RemoteExecution::MayHaveStarted);
        session.close_with_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn spawned_process_without_status_reports_unknown() {
        let server = start_blocking_server();
        let session = blocking_session(&server);
        let (_cancel_sender, cancel) = exec_cancellation();

        let process = session
            .start_process(
                b"no-status".to_vec(),
                ProcessConfig {
                    stdin: crate::ProcessStdin::Ignore,
                    capture_stdout: true,
                    capture_stderr: true,
                },
                None,
                cancel,
            )
            .unwrap();
        assert_eq!(process.read_stdout(1024).unwrap().unwrap(), b"tail");
        let exit = process.wait_exit().unwrap();
        assert_eq!(exit.status, ExitStatus::Unknown);
        assert_eq!(exit.remote_execution, RemoteExecution::MayHaveStarted);
        process.wait_closed();
        session.close_with_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn connection_loss_before_status_rejects_process_exit() {
        let server = start_blocking_server();
        let session = blocking_session(&server);
        let (_cancel_sender, cancel) = exec_cancellation();

        let process = session
            .start_process(
                b"lost-before-status".to_vec(),
                ProcessConfig {
                    stdin: crate::ProcessStdin::Ignore,
                    capture_stdout: true,
                    capture_stderr: true,
                },
                None,
                cancel,
            )
            .unwrap();
        let error = process.wait_exit().unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_CONNECTION_LOST");
        assert_eq!(error.phase(), "io");
        assert_eq!(error.remote_execution(), RemoteExecution::MayHaveStarted);
        process.wait_closed();
    }

    #[test]
    fn preserves_a_server_exit_signal_and_core_dump_flag() {
        let server = start_blocking_server();
        let session = blocking_session(&server);
        let (_cancel_sender, cancel) = exec_cancellation();

        let result = session
            .exec_with_cancel(b"signal-status".to_vec(), Vec::new(), None, 1024, cancel)
            .unwrap();
        assert_eq!(
            result.exit_status,
            ExitStatus::Signal {
                signal: "TERM".into(),
                core_dumped: true,
            }
        );
        assert_eq!(result.remote_execution, RemoteExecution::ExitObserved);
        session.close_with_timeout(Duration::from_secs(5)).unwrap();
    }

    #[tokio::test]
    async fn dns_failure_reports_the_dns_phase() {
        let config = Config::new(
            "a".repeat(300),
            22,
            USERNAME.to_string(),
            crate::HostKeyPolicy::Pinned(vec!["SHA256:pending".into()]),
            password_auth(),
            1_000,
            1_000,
            DEFAULT_MAX_CHANNELS,
            DEFAULT_MAX_PENDING_OPERATIONS,
            1_000,
        )
        .unwrap();
        let error = connect_transport(&config.transport())
            .await
            .err()
            .expect("DNS lookup unexpectedly succeeded");
        assert_eq!(error.phase(), "dns");
    }

    #[tokio::test]
    async fn tcp_failure_reports_the_tcp_phase() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = Config::new(
            "127.0.0.1".to_string(),
            port,
            USERNAME.to_string(),
            crate::HostKeyPolicy::Pinned(vec!["SHA256:pending".into()]),
            password_auth(),
            1_000,
            1_000,
            DEFAULT_MAX_CHANNELS,
            DEFAULT_MAX_PENDING_OPERATIONS,
            1_000,
        )
        .unwrap();
        let error = connect_transport(&config.transport())
            .await
            .err()
            .expect("TCP connection unexpectedly succeeded");
        assert_eq!(error.code(), "ERR_SSH_CONNECT");
        assert_eq!(error.phase(), "tcp");
    }
}
