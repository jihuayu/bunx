//! Protocol and policy layer for `Bun.SSH`.
//!
//! This crate deliberately has no JavaScriptCore dependency. Tokio and russh
//! stay behind this API so the JSC bridge can keep all protocol state off the
//! JavaScript thread.

pub mod config;
pub mod host_key;
pub mod process;
pub mod session;

pub use config::{Auth, Config, HostKeyPolicy, KnownHostsSource, Secret, TransportConfig};
pub use host_key::{HostKeyError, HostKeyVerifier, KnownHosts, PinnedHostKeys};
pub use process::{
    BlockingProcess, OutputBudget, ProcessConfig, ProcessError, ProcessExit, ProcessStdin,
};
pub use session::{
    AuthError, BlockingSession, CloseError, CloseResult, ConnectError, ConnectionInfo,
    ExecCancelReceiver, ExecCancelSender, ExecError, ExecResult, ExitStatus, RemoteExecution,
    Session, exec_cancellation,
};
