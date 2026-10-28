use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use russh::client::Msg;
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Sig};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};

use crate::session::{ExecCancelReceiver, ExitStatus, RemoteExecution};

const MAX_OUTPUT_STREAM_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CONNECTION_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const INPUT_QUEUE_CAPACITY: usize = 8;

#[derive(Clone)]
pub(crate) struct OutputBudget {
    used: Arc<std::sync::Mutex<usize>>,
    limit: usize,
}

impl Default for OutputBudget {
    fn default() -> Self {
        Self::with_limit(MAX_CONNECTION_OUTPUT_BYTES)
    }
}

impl OutputBudget {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            used: Arc::new(std::sync::Mutex::new(0)),
            limit,
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    pub(crate) fn try_reserve(&self, bytes: usize) -> bool {
        let mut used = self.used.lock().unwrap_or_else(|error| error.into_inner());
        let Some(next) = used.checked_add(bytes) else {
            return false;
        };
        if next > self.limit {
            return false;
        }
        *used = next;
        true
    }

    pub(crate) fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut used = self.used.lock().unwrap_or_else(|error| error.into_inner());
        debug_assert!(*used >= bytes, "SSH output budget released twice");
        *used = used.saturating_sub(bytes);
    }

    #[cfg(test)]
    fn used(&self) -> usize {
        *self.used.lock().unwrap_or_else(|error| error.into_inner())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessError {
    code: &'static str,
    phase: &'static str,
    message: String,
    remote_execution: RemoteExecution,
}

impl ProcessError {
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
            remote_execution,
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn phase(&self) -> &'static str {
        self.phase
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn remote_execution(&self) -> RemoteExecution {
        self.remote_execution
    }
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProcessError {}

#[derive(Clone, Debug)]
pub struct ProcessExit {
    pub status: ExitStatus,
    pub remote_execution: RemoteExecution,
}

#[derive(Clone, Debug)]
pub enum ProcessStdin {
    Ignore,
    Pipe,
    Data(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct ProcessConfig {
    pub stdin: ProcessStdin,
    pub capture_stdout: bool,
    pub capture_stderr: bool,
}

struct OutputState {
    chunks: VecDeque<Vec<u8>>,
    bytes: usize,
    done: bool,
    discard: bool,
    error: Option<ProcessError>,
    budget: OutputBudget,
}

impl OutputState {
    fn new(discard: bool, budget: OutputBudget) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            done: discard,
            discard,
            error: None,
            budget,
        }
    }
}

impl Drop for OutputState {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
        self.bytes = 0;
    }
}

struct OutputPipe {
    name: &'static str,
    state: AsyncMutex<OutputState>,
    changed: watch::Sender<u64>,
}

impl OutputPipe {
    fn new(name: &'static str, discard: bool, budget: OutputBudget) -> Self {
        Self {
            name,
            state: AsyncMutex::new(OutputState::new(discard, budget)),
            changed: watch::channel(0).0,
        }
    }

    fn touch(&self) {
        self.changed.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    async fn push(&self, mut data: Vec<u8>, remote_execution: RemoteExecution) {
        if data.is_empty() {
            return;
        }

        let mut state = self.state.lock().await;
        if state.done || state.discard {
            return;
        }

        let original_len = data.len();
        let remaining = MAX_OUTPUT_STREAM_BYTES.saturating_sub(state.bytes);
        let retained = original_len.min(remaining);
        if retained != 0 && !state.budget.try_reserve(retained) {
            state.done = true;
            if state.error.is_none() {
                state.error = Some(ProcessError::new(
                    "ERR_SSH_RESOURCE_LIMIT",
                    "io",
                    format!(
                        "SSH connection output budget of {} bytes was exceeded",
                        state.budget.limit()
                    ),
                    remote_execution,
                ));
            }
            drop(state);
            self.touch();
            return;
        }
        if retained != 0 {
            data.truncate(retained);
            state.bytes += retained;
            state.chunks.push_back(data);
        }
        if remaining == 0 || retained < original_len {
            state.done = true;
            if state.error.is_none() {
                state.error = Some(ProcessError::new(
                    "ERR_SSH_OUTPUT_LIMIT",
                    "io",
                    format!(
                        "SSH process {} consumer did not keep up within the {}-byte buffer",
                        self.name, MAX_OUTPUT_STREAM_BYTES
                    ),
                    remote_execution,
                ));
            }
        }
        drop(state);
        self.touch();
    }

    async fn read(&self, max_bytes: usize) -> Result<Option<Vec<u8>>, ProcessError> {
        let max_bytes = max_bytes.max(1);
        loop {
            let mut changed = self.changed.subscribe();
            let mut state = self.state.lock().await;
            if let Some(chunk) = state.chunks.pop_front() {
                state.bytes = state.bytes.saturating_sub(chunk.len());
                let output = if chunk.len() > max_bytes {
                    let mut chunk = chunk;
                    let rest = chunk.split_off(max_bytes);
                    state.bytes += rest.len();
                    state.chunks.push_front(rest);
                    chunk
                } else {
                    chunk
                };
                state.budget.release(output.len());
                drop(state);
                self.touch();
                return Ok(Some(output));
            }
            if state.done {
                return match state.error.as_ref() {
                    Some(error) => Err(error.clone()),
                    None => Ok(None),
                };
            }
            drop(state);
            changed.changed().await.map_err(|_| {
                ProcessError::new(
                    "ERR_SSH_CONNECTION_LOST",
                    "io",
                    "SSH process output ended unexpectedly",
                    RemoteExecution::MayHaveStarted,
                )
            })?;
        }
    }

    async fn finish(&self, error: Option<ProcessError>) {
        let mut state = self.state.lock().await;
        state.done = true;
        if state.error.is_none() {
            state.error = error;
        }
        drop(state);
        self.touch();
    }

    async fn discard(&self) {
        let mut state = self.state.lock().await;
        state.budget.release(state.bytes);
        state.chunks.clear();
        state.bytes = 0;
        state.done = true;
        state.discard = true;
        drop(state);
        self.touch();
    }
}

enum InputCommand {
    Write(Vec<u8>, oneshot::Sender<Result<(), ProcessError>>),
    Eof(oneshot::Sender<Result<(), ProcessError>>),
    Signal(Sig, oneshot::Sender<Result<(), ProcessError>>),
}

struct ProcessInner {
    stdout: OutputPipe,
    stderr: OutputPipe,
    stdin: mpsc::Sender<InputCommand>,
    cancel: watch::Sender<bool>,
    exit: watch::Sender<ProcessExitState>,
    closed: watch::Sender<bool>,
    remote_execution: AtomicU8,
}

#[derive(Clone, Debug)]
enum ProcessExitState {
    Pending,
    Ready(ProcessExit),
    Failed(ProcessError),
}

impl ProcessInner {
    fn remote_execution(&self) -> RemoteExecution {
        match self.remote_execution.load(Ordering::Acquire) {
            2 => RemoteExecution::ExitObserved,
            1 => RemoteExecution::MayHaveStarted,
            _ => RemoteExecution::NotStarted,
        }
    }

    fn set_remote_execution(&self, value: RemoteExecution) {
        let value = match value {
            RemoteExecution::NotStarted => 0,
            RemoteExecution::MayHaveStarted => 1,
            RemoteExecution::ExitObserved => 2,
        };
        self.remote_execution.store(value, Ordering::Release);
    }

    async fn send_input(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), ProcessError>>) -> InputCommand,
    ) -> Result<(), ProcessError> {
        let mut closed = self.closed.subscribe();
        let mut cancel = self.cancel.subscribe();
        if *closed.borrow() || *cancel.borrow() {
            return Err(closed_error());
        }

        let (sender, receiver) = oneshot::channel();
        tokio::select! {
            result = self.stdin.send(make(sender)) => {
                result.map_err(|_| closed_error())?;
            }
            _ = closed.changed() => return Err(closed_error()),
            _ = cancel.changed() => return Err(closed_error()),
        }

        tokio::select! {
            result = receiver => result.map_err(|_| {
                ProcessError::new(
                    "ERR_SSH_CONNECTION_LOST",
                    "io",
                    "SSH process closed before completing stdin",
                    self.remote_execution(),
                )
            })?,
            _ = closed.changed() => Err(closed_error()),
            _ = cancel.changed() => Err(closed_error()),
        }
    }
}

pub struct BlockingProcess {
    runtime: Arc<tokio::runtime::Runtime>,
    inner: Arc<ProcessInner>,
}

impl BlockingProcess {
    pub fn read_stdout(&self, max_bytes: usize) -> Result<Option<Vec<u8>>, ProcessError> {
        self.runtime.block_on(self.inner.stdout.read(max_bytes))
    }

    pub fn read_stderr(&self, max_bytes: usize) -> Result<Option<Vec<u8>>, ProcessError> {
        self.runtime.block_on(self.inner.stderr.read(max_bytes))
    }

    pub fn discard_stdout(&self) {
        self.runtime.block_on(self.inner.stdout.discard());
    }

    pub fn discard_stderr(&self) {
        self.runtime.block_on(self.inner.stderr.discard());
    }

    pub fn write_stdin(&self, data: Vec<u8>) -> Result<(), ProcessError> {
        self.runtime.block_on(
            self.inner
                .send_input(|sender| InputCommand::Write(data, sender)),
        )
    }

    pub fn close_stdin(&self) -> Result<(), ProcessError> {
        self.runtime
            .block_on(self.inner.send_input(InputCommand::Eof))
    }

    pub fn send_signal(&self, signal: &str) -> Result<(), ProcessError> {
        let signal = parse_signal(signal)?;
        self.runtime.block_on(
            self.inner
                .send_input(|sender| InputCommand::Signal(signal, sender)),
        )
    }

    pub fn cancel(&self) -> bool {
        if *self.inner.cancel.borrow() {
            return false;
        }
        self.inner.cancel.send_replace(true);
        true
    }

    pub fn remote_execution(&self) -> RemoteExecution {
        self.inner.remote_execution()
    }

    pub fn wait_exit(&self) -> Result<ProcessExit, ProcessError> {
        self.runtime.block_on(async {
            let mut exit = self.inner.exit.subscribe();
            loop {
                match exit.borrow().clone() {
                    ProcessExitState::Ready(exit) => return Ok(exit),
                    ProcessExitState::Failed(error) => return Err(error),
                    ProcessExitState::Pending => {}
                }
                if exit.changed().await.is_err() {
                    return Ok(ProcessExit {
                        status: ExitStatus::Unknown,
                        remote_execution: self.inner.remote_execution(),
                    });
                }
            }
        })
    }

    pub fn wait_closed(&self) {
        self.runtime.block_on(async {
            let mut closed = self.inner.closed.subscribe();
            loop {
                if *closed.borrow() {
                    return;
                }
                if closed.changed().await.is_err() {
                    return;
                }
            }
        });
    }
}

impl Drop for BlockingProcess {
    fn drop(&mut self) {
        self.inner.cancel.send_replace(true);
    }
}

pub(crate) fn start_driver(
    channel: Channel<Msg>,
    runtime: Arc<tokio::runtime::Runtime>,
    config: ProcessConfig,
    output_budget: OutputBudget,
    external_cancel: ExecCancelReceiver,
    initial_messages: Vec<ChannelMsg>,
) -> BlockingProcess {
    let (read_half, write_half) = channel.split();
    let (input_sender, input_receiver) = mpsc::channel(INPUT_QUEUE_CAPACITY);
    let cancelled = *external_cancel.borrow();
    let (cancel_sender, cancel_receiver) = watch::channel(cancelled);
    let (exit_sender, _) = watch::channel(ProcessExitState::Pending);
    let (closed_sender, _) = watch::channel(false);
    let inner = Arc::new(ProcessInner {
        stdout: OutputPipe::new("stdout", !config.capture_stdout, output_budget.clone()),
        stderr: OutputPipe::new("stderr", !config.capture_stderr, output_budget),
        stdin: input_sender,
        cancel: cancel_sender,
        exit: exit_sender,
        closed: closed_sender,
        remote_execution: AtomicU8::new(1),
    });

    let forward_cancel = Arc::clone(&inner);
    tokio::spawn(async move {
        let mut external_cancel = external_cancel;
        if *external_cancel.borrow() {
            forward_cancel.cancel.send_replace(true);
            return;
        }
        loop {
            if external_cancel.changed().await.is_err() {
                return;
            }
            if *external_cancel.borrow() {
                forward_cancel.cancel.send_replace(true);
                return;
            }
        }
    });

    let (writer_error_sender, writer_error_receiver) = mpsc::unbounded_channel();
    tokio::spawn(run_input_writer(
        write_half,
        input_receiver,
        config.stdin,
        cancel_receiver.clone(),
        writer_error_sender,
    ));
    tokio::spawn(run_process_driver(
        read_half,
        cancel_receiver,
        writer_error_receiver,
        initial_messages,
        Arc::clone(&inner),
    ));

    BlockingProcess { runtime, inner }
}

async fn run_process_driver(
    mut read_half: ChannelReadHalf,
    mut cancel: watch::Receiver<bool>,
    mut writer_error: mpsc::UnboundedReceiver<ProcessError>,
    initial_messages: Vec<ChannelMsg>,
    inner: Arc<ProcessInner>,
) {
    let mut status = None;
    let mut clean_close = false;
    let mut failure = None;

    for message in initial_messages {
        if !handle_process_message(message, &inner, &mut status, &mut clean_close).await {
            break;
        }
    }

    while !clean_close && !*cancel.borrow() {
        tokio::select! {
            message = read_half.wait() => {
                let Some(message) = message else {
                    if !*cancel.borrow() {
                        failure = Some(ProcessError::new(
                            "ERR_SSH_CONNECTION_LOST",
                            "io",
                            "SSH connection was lost before the process channel closed",
                            inner.remote_execution(),
                        ));
                    }
                    break;
                };
                if !handle_process_message(message, &inner, &mut status, &mut clean_close).await {
                    break;
                }
            }
            result = cancel.changed() => {
                let _ = result;
                failure = Some(cancelled_error());
                break;
            }
            error = writer_error.recv() => {
                if let Some(error) = error {
                    failure = Some(error);
                }
                break;
            }
        }
    }

    let was_cancelled = *cancel.borrow();
    inner.cancel.send_replace(true);

    if failure.is_none() && was_cancelled && status.is_none() {
        failure = Some(cancelled_error());
    }
    let exit_observed = status.is_some();
    let status = status.unwrap_or(ExitStatus::Unknown);
    let remote_execution = if exit_observed {
        RemoteExecution::ExitObserved
    } else {
        inner.remote_execution()
    };
    inner.set_remote_execution(remote_execution);
    let exit = ProcessExit {
        status,
        remote_execution,
    };
    let exit_state = match failure.clone() {
        Some(error) => ProcessExitState::Failed(error),
        None => ProcessExitState::Ready(exit),
    };
    inner.exit.send_if_modified(|current| {
        if matches!(current, ProcessExitState::Pending) {
            *current = exit_state.clone();
            true
        } else {
            false
        }
    });
    inner.stdout.finish(failure.clone()).await;
    inner.stderr.finish(failure).await;
    inner.closed.send_replace(true);
}

async fn handle_process_message(
    message: ChannelMsg,
    inner: &Arc<ProcessInner>,
    status: &mut Option<ExitStatus>,
    clean_close: &mut bool,
) -> bool {
    match message {
        ChannelMsg::Data { data } => {
            inner
                .stdout
                .push(data.to_vec(), inner.remote_execution())
                .await;
        }
        ChannelMsg::ExtendedData { data, ext } if ext == 1 => {
            inner
                .stderr
                .push(data.to_vec(), inner.remote_execution())
                .await;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            if status.is_none() {
                *status = Some(ExitStatus::Exit { code: exit_status });
            }
            inner.set_remote_execution(RemoteExecution::ExitObserved);
            inner
                .exit
                .send_replace(ProcessExitState::Ready(ProcessExit {
                    status: status.clone().unwrap_or(ExitStatus::Unknown),
                    remote_execution: RemoteExecution::ExitObserved,
                }));
        }
        ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            ..
        } => {
            if status.is_none() {
                *status = Some(ExitStatus::Signal {
                    signal: signal_name_name(&signal_name),
                    core_dumped,
                });
            }
            inner.set_remote_execution(RemoteExecution::ExitObserved);
            inner
                .exit
                .send_replace(ProcessExitState::Ready(ProcessExit {
                    status: status.clone().unwrap_or(ExitStatus::Unknown),
                    remote_execution: RemoteExecution::ExitObserved,
                }));
        }
        ChannelMsg::Close => {
            *clean_close = true;
            return false;
        }
        ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. } => {}
        ChannelMsg::OpenFailure(_) => {
            inner.cancel.send_replace(true);
            return false;
        }
        _ => {}
    }
    true
}

async fn run_input_writer(
    write_half: ChannelWriteHalf<Msg>,
    mut input: mpsc::Receiver<InputCommand>,
    initial: ProcessStdin,
    cancel: watch::Receiver<bool>,
    errors: mpsc::UnboundedSender<ProcessError>,
) {
    let mut cancel_changed = cancel.clone();
    if *cancel_changed.borrow() {
        let _ = write_half.close().await;
        return;
    }

    let mut stdin_open = true;
    match initial {
        ProcessStdin::Ignore => {
            stdin_open = false;
            if let Err(error) = write_half.eof().await {
                if !*cancel_changed.borrow() {
                    let _ = errors.send(writer_error("failed to close SSH stdin", error));
                }
                let _ = write_half.close().await;
                return;
            }
        }
        ProcessStdin::Pipe => {}
        ProcessStdin::Data(data) => {
            if !*cancel_changed.borrow() {
                let result = tokio::select! {
                    result = write_half.data_bytes(data) => Some(result),
                    result = cancel_changed.changed() => {
                        let _ = result;
                        None
                    }
                };
                if let Some(Err(error)) = result {
                    let _ = errors.send(writer_error("failed to write SSH stdin", error));
                    let _ = write_half.close().await;
                    return;
                }
                if result.is_none() {
                    let _ = write_half.close().await;
                    return;
                }
            }
            stdin_open = false;
            if let Err(error) = write_half.eof().await {
                if !*cancel_changed.borrow() {
                    let _ = errors.send(writer_error("failed to close SSH stdin", error));
                }
                let _ = write_half.close().await;
                return;
            }
        }
    }

    loop {
        if *cancel_changed.borrow() {
            let _ = write_half.close().await;
            return;
        }
        tokio::select! {
            result = cancel_changed.changed() => {
                let _ = result;
                let _ = write_half.close().await;
                return;
            }
            command = input.recv() => {
                let Some(command) = command else {
                    if stdin_open {
                        let _ = write_half.eof().await;
                    }
                    let _ = write_half.close().await;
                    return;
                };
                match command {
                    InputCommand::Write(data, reply) => {
                        if !stdin_open {
                            let _ = reply.send(Err(ProcessError::new(
                                "ERR_SSH_IO",
                                "io",
                                "SSH stdin is already closed",
                                RemoteExecution::MayHaveStarted,
                            )));
                            continue;
                        }
                        let result = tokio::select! {
                            result = write_half.data_bytes(data) => result,
                            result = cancel_changed.changed() => {
                                let _ = result;
                                let _ = write_half.close().await;
                                let _ = reply.send(Err(closed_error()));
                                return;
                            }
                        };
                        match result {
                            Ok(()) => {
                                let _ = reply.send(Ok(()));
                            }
                            Err(error) => {
                                let error = writer_error("failed to write SSH stdin", error);
                                let _ = reply.send(Err(error.clone()));
                                let _ = errors.send(error);
                                let _ = write_half.close().await;
                                return;
                            }
                        }
                    }
                    InputCommand::Eof(reply) => {
                        if stdin_open {
                            if let Err(error) = write_half.eof().await {
                                let error = writer_error("failed to close SSH stdin", error);
                                let _ = reply.send(Err(error.clone()));
                                let _ = errors.send(error);
                                let _ = write_half.close().await;
                                return;
                            }
                            stdin_open = false;
                        }
                        let _ = reply.send(Ok(()));
                    }
                    InputCommand::Signal(signal, reply) => {
                        match write_half.signal(signal).await {
                            Ok(()) => {
                                let _ = reply.send(Ok(()));
                            }
                            Err(error) => {
                                let error = writer_error("failed to send SSH signal", error);
                                let _ = reply.send(Err(error.clone()));
                                let _ = errors.send(error);
                                let _ = write_half.close().await;
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn writer_error(message: &str, error: russh::Error) -> ProcessError {
    let code = if matches!(
        &error,
        russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::SendError
            | russh::Error::IO(_)
    ) {
        "ERR_SSH_CONNECTION_LOST"
    } else {
        "ERR_SSH_IO"
    };
    ProcessError::new(
        code,
        "io",
        format!("{message}: {error}"),
        RemoteExecution::MayHaveStarted,
    )
}

fn closed_error() -> ProcessError {
    ProcessError::new(
        "ERR_SSH_CLOSED",
        "io",
        "SSH process is closed",
        RemoteExecution::MayHaveStarted,
    )
}

fn cancelled_error() -> ProcessError {
    ProcessError::new(
        "ERR_SSH_ABORTED",
        "exec",
        "SSH process was cancelled",
        RemoteExecution::MayHaveStarted,
    )
}

fn parse_signal(value: &str) -> Result<Sig, ProcessError> {
    let signal = match value {
        "ABRT" => Sig::ABRT,
        "ALRM" => Sig::ALRM,
        "FPE" => Sig::FPE,
        "HUP" => Sig::HUP,
        "ILL" => Sig::ILL,
        "INT" => Sig::INT,
        "KILL" => Sig::KILL,
        "PIPE" => Sig::PIPE,
        "QUIT" => Sig::QUIT,
        "SEGV" => Sig::SEGV,
        "TERM" => Sig::TERM,
        "USR1" => Sig::USR1,
        "USR2" => Sig::Custom("USR2".into()),
        _ => {
            return Err(ProcessError::new(
                "ERR_SSH_CONFIG",
                "config",
                format!("unsupported SSH signal {value:?}"),
                RemoteExecution::NotStarted,
            ));
        }
    };
    Ok(signal)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn output_budget_is_released_as_output_is_consumed() {
        let budget = OutputBudget::with_limit(4);
        let pipe = OutputPipe::new("stdout", false, budget.clone());

        pipe.push(vec![1; 3], RemoteExecution::MayHaveStarted).await;
        assert_eq!(budget.used(), 3);
        assert_eq!(pipe.read(2).await.unwrap().unwrap().len(), 2);
        assert_eq!(budget.used(), 1);
        assert_eq!(pipe.read(2).await.unwrap().unwrap().len(), 1);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn output_budget_rejects_output_above_the_shared_limit() {
        let budget = OutputBudget::with_limit(4);
        let first = OutputPipe::new("stdout", false, budget.clone());
        let second = OutputPipe::new("stdout", false, budget.clone());

        first
            .push(vec![1; 3], RemoteExecution::MayHaveStarted)
            .await;
        second
            .push(vec![2; 2], RemoteExecution::MayHaveStarted)
            .await;

        let error = second.read(2).await.unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_RESOURCE_LIMIT");
        assert_eq!(budget.used(), 3);
        first.discard().await;
        assert_eq!(budget.used(), 0);
    }
}
