use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use russh::client::Msg;
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Sig};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};

use crate::session::{ExecCancelReceiver, ExitStatus, RemoteExecution};

const MAX_CHANNEL_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_STREAM_BYTES: usize = 256 * 1024;
pub const MAX_CONNECTION_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const INPUT_QUEUE_CAPACITY: usize = 8;
const OUTPUT_BACKPRESSURE_WAIT: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct OutputBudget {
    used: Arc<AtomicUsize>,
    limit: usize,
    resource: &'static str,
    parent: Option<Arc<OutputBudget>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputBudgetLimit {
    pub resource: &'static str,
    pub limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputBudgetReservation {
    pub bytes: usize,
    pub limit: Option<OutputBudgetLimit>,
}

impl Default for OutputBudget {
    fn default() -> Self {
        Self::with_limit(MAX_CONNECTION_OUTPUT_BYTES)
    }
}

impl OutputBudget {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self::with_parent(limit, "connection", None)
    }

    pub fn vm(limit: usize) -> Self {
        Self::with_parent(limit, "VM", None)
    }

    pub fn connection(parent: OutputBudget) -> Self {
        Self::with_parent(MAX_CONNECTION_OUTPUT_BYTES, "connection", Some(parent))
    }

    fn with_parent(limit: usize, resource: &'static str, parent: Option<OutputBudget>) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit,
            resource,
            parent: parent.map(Arc::new),
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    pub(crate) fn limit_info(&self) -> OutputBudgetLimit {
        OutputBudgetLimit {
            resource: self.resource,
            limit: self.limit,
        }
    }

    fn available(&self) -> usize {
        let local = self.limit.saturating_sub(self.used());
        match self.parent.as_deref() {
            Some(parent) => local.min(parent.available()),
            None => local,
        }
    }

    #[cfg(test)]
    pub(crate) fn try_reserve(&self, bytes: usize) -> bool {
        self.try_reserve_up_to(bytes).bytes == bytes
    }

    pub(crate) fn try_reserve_up_to(&self, bytes: usize) -> OutputBudgetReservation {
        let parent_reservation = match self.parent.as_deref() {
            Some(parent) => parent.try_reserve_up_to(bytes),
            None => OutputBudgetReservation { bytes, limit: None },
        };
        let reserved = self.reserve_up_to(parent_reservation.bytes);
        if reserved < parent_reservation.bytes
            && let Some(parent) = self.parent.as_deref()
        {
            parent.release(parent_reservation.bytes - reserved);
        }

        if let Some(limit) = parent_reservation.limit {
            OutputBudgetReservation {
                bytes: reserved,
                limit: Some(limit),
            }
        } else if reserved < bytes {
            OutputBudgetReservation {
                bytes: reserved,
                limit: Some(self.limit_info()),
            }
        } else {
            OutputBudgetReservation {
                bytes: reserved,
                limit: None,
            }
        }
    }

    fn reserve_up_to(&self, bytes: usize) -> usize {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let reservation = bytes.min(self.limit.saturating_sub(used));
            if reservation == 0 {
                return 0;
            }
            match self.used.compare_exchange_weak(
                used,
                used + reservation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return reservation,
                Err(actual) => used = actual,
            }
        }
    }

    pub(crate) fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes, "SSH output budget released twice");
        if let Some(parent) = self.parent.as_deref() {
            parent.release(bytes);
        }
    }

    fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
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
    channel_budget: OutputBudget,
    connection_budget: OutputBudget,
}

impl OutputState {
    fn new(discard: bool, channel_budget: OutputBudget, connection_budget: OutputBudget) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            done: discard,
            discard,
            error: None,
            channel_budget,
            connection_budget,
        }
    }
}

impl Drop for OutputState {
    fn drop(&mut self) {
        self.channel_budget.release(self.bytes);
        self.connection_budget.release(self.bytes);
        self.bytes = 0;
    }
}

struct OutputPipe {
    name: &'static str,
    state: AsyncMutex<OutputState>,
    changed: watch::Sender<u64>,
}

impl OutputPipe {
    fn new(
        name: &'static str,
        discard: bool,
        channel_budget: OutputBudget,
        connection_budget: OutputBudget,
    ) -> Self {
        Self {
            name,
            state: AsyncMutex::new(OutputState::new(discard, channel_budget, connection_budget)),
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

        let mut changed = self.changed.subscribe();
        let deadline = tokio::time::Instant::now() + OUTPUT_BACKPRESSURE_WAIT;
        loop {
            let mut state = self.state.lock().await;
            if state.done || state.discard {
                return;
            }

            let available = (MAX_OUTPUT_STREAM_BYTES - state.bytes)
                .min(state.channel_budget.available())
                .min(state.connection_budget.available());
            if available >= data.len() && self.try_append(&mut state, &data) {
                drop(state);
                self.touch();
                return;
            }
            drop(state);

            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::select! {
                _ = changed.changed() => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }

        let mut state = self.state.lock().await;
        if state.done || state.discard {
            return;
        }
        self.append_limited(&mut state, &mut data, remote_execution);
        drop(state);
        self.touch();
    }

    fn try_append(&self, state: &mut OutputState, data: &[u8]) -> bool {
        let channel_reservation = state.channel_budget.try_reserve_up_to(data.len());
        let connection_reservation = state
            .connection_budget
            .try_reserve_up_to(channel_reservation.bytes);
        if connection_reservation.bytes != data.len() {
            state.channel_budget.release(channel_reservation.bytes);
            state
                .connection_budget
                .release(connection_reservation.bytes);
            return false;
        }

        state.bytes += data.len();
        state.chunks.push_back(data.to_vec());
        true
    }

    fn append_limited(
        &self,
        state: &mut OutputState,
        data: &mut Vec<u8>,
        remote_execution: RemoteExecution,
    ) {
        let original_len = data.len();
        let stream_reserved = original_len.min(MAX_OUTPUT_STREAM_BYTES.saturating_sub(state.bytes));
        let channel_reserved = state
            .channel_budget
            .try_reserve_up_to(stream_reserved)
            .bytes;
        let connection_reservation = state.connection_budget.try_reserve_up_to(channel_reserved);
        if connection_reservation.bytes < channel_reserved {
            state
                .channel_budget
                .release(channel_reserved - connection_reservation.bytes);
        }
        let retained = connection_reservation.bytes;
        if retained != 0 {
            data.truncate(retained);
            state.bytes += retained;
            state.chunks.push_back(std::mem::take(data));
        }
        if retained == original_len {
            return;
        }

        state.done = true;
        if state.error.is_some() {
            return;
        }
        state.error = Some(if let Some(limit) = connection_reservation.limit {
            ProcessError::new(
                "ERR_SSH_RESOURCE_LIMIT",
                "io",
                format!(
                    "SSH {} output budget of {} bytes was exceeded",
                    limit.resource, limit.limit
                ),
                remote_execution,
            )
        } else if channel_reserved < stream_reserved {
            ProcessError::new(
                "ERR_SSH_OUTPUT_LIMIT",
                "io",
                format!(
                    "SSH process output exceeded the {}-byte channel buffer",
                    state.channel_budget.limit()
                ),
                remote_execution,
            )
        } else {
            ProcessError::new(
                "ERR_SSH_OUTPUT_LIMIT",
                "io",
                format!(
                    "SSH process {} exceeded its {}-byte output buffer",
                    self.name, MAX_OUTPUT_STREAM_BYTES
                ),
                remote_execution,
            )
        });
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
                state.channel_budget.release(output.len());
                state.connection_budget.release(output.len());
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
        state.channel_budget.release(state.bytes);
        state.connection_budget.release(state.bytes);
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
    let channel_budget = OutputBudget::with_limit(MAX_CHANNEL_OUTPUT_BYTES);
    let inner = Arc::new(ProcessInner {
        stdout: OutputPipe::new(
            "stdout",
            !config.capture_stdout,
            channel_budget.clone(),
            output_budget.clone(),
        ),
        stderr: OutputPipe::new(
            "stderr",
            !config.capture_stderr,
            channel_budget,
            output_budget,
        ),
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
        let channel_budget = OutputBudget::with_limit(4);
        let connection_budget = OutputBudget::with_limit(4);
        let pipe = OutputPipe::new(
            "stdout",
            false,
            channel_budget.clone(),
            connection_budget.clone(),
        );

        pipe.push(vec![1; 3], RemoteExecution::MayHaveStarted).await;
        assert_eq!(channel_budget.used(), 3);
        assert_eq!(connection_budget.used(), 3);
        assert_eq!(pipe.read(2).await.unwrap().unwrap().len(), 2);
        assert_eq!(channel_budget.used(), 1);
        assert_eq!(connection_budget.used(), 1);
        assert_eq!(pipe.read(2).await.unwrap().unwrap().len(), 1);
        assert_eq!(channel_budget.used(), 0);
        assert_eq!(connection_budget.used(), 0);
    }

    #[tokio::test]
    async fn output_budget_rejects_output_above_the_shared_limit() {
        let channel_budget = OutputBudget::with_limit(8);
        let connection_budget = OutputBudget::with_limit(4);
        let first = OutputPipe::new(
            "stdout",
            false,
            channel_budget.clone(),
            connection_budget.clone(),
        );
        let second = OutputPipe::new("stderr", false, channel_budget, connection_budget.clone());

        first
            .push(vec![1; 3], RemoteExecution::MayHaveStarted)
            .await;
        second
            .push(vec![2; 2], RemoteExecution::MayHaveStarted)
            .await;

        assert_eq!(second.read(2).await.unwrap().unwrap().len(), 1);
        let error = second.read(2).await.unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_RESOURCE_LIMIT");
        assert_eq!(connection_budget.used(), 3);
        first.discard().await;
        assert_eq!(connection_budget.used(), 0);
    }

    #[test]
    fn connection_budgets_share_and_release_a_vm_budget() {
        let vm_budget = OutputBudget::vm(6);
        let first = OutputBudget::with_parent(4, "connection", Some(vm_budget.clone()));
        let second = OutputBudget::with_parent(4, "connection", Some(vm_budget.clone()));

        assert!(first.try_reserve(4));
        let reservation = second.try_reserve_up_to(3);
        assert_eq!(reservation.bytes, 2);
        assert_eq!(
            reservation.limit,
            Some(OutputBudgetLimit {
                resource: "VM",
                limit: 6
            })
        );
        let reservation = first.try_reserve_up_to(1);
        assert_eq!(reservation.bytes, 0);
        assert_eq!(
            reservation.limit,
            Some(OutputBudgetLimit {
                resource: "VM",
                limit: 6
            })
        );
        first.release(4);
        second.release(2);

        assert!(first.try_reserve(4));
        assert_eq!(
            second.try_reserve_up_to(3).limit,
            Some(OutputBudgetLimit {
                resource: "VM",
                limit: 6
            })
        );

        let vm_budget = OutputBudget::vm(100);
        let connection = OutputBudget::with_parent(4, "connection", Some(vm_budget));
        assert!(connection.try_reserve(4));
        assert_eq!(
            connection.try_reserve_up_to(1).limit,
            Some(OutputBudgetLimit {
                resource: "connection",
                limit: 4
            })
        );
    }

    #[tokio::test]
    async fn channel_output_limit_is_shared_by_stdout_and_stderr() {
        let channel_budget = OutputBudget::with_limit(4);
        let connection_budget = OutputBudget::with_limit(16);
        let stdout = OutputPipe::new(
            "stdout",
            false,
            channel_budget.clone(),
            connection_budget.clone(),
        );
        let stderr = OutputPipe::new("stderr", false, channel_budget, connection_budget);

        stdout
            .push(vec![1; 3], RemoteExecution::MayHaveStarted)
            .await;
        stderr
            .push(vec![2; 2], RemoteExecution::MayHaveStarted)
            .await;

        assert_eq!(stderr.read(2).await.unwrap().unwrap().len(), 1);
        let error = stderr.read(2).await.unwrap_err();
        assert_eq!(error.code(), "ERR_SSH_OUTPUT_LIMIT");
    }
}
