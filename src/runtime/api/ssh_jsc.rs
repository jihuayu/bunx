use bun_jsc::bindgen::{self, JsHeap, JsScope};
use bun_jsc::{JSGlobalObject, JSPromiseStrong, JSValue, Job, JobContext, JsAffine, JsResult};
use bun_ssh::{
    Auth, AuthError, BlockingProcess, BlockingSession, CloseError, CloseResult, ConnectError,
    ConnectionInfo, ExecCancelReceiver, ExecCancelSender, ExecError, ExecResult, ExitStatus,
    HostKeyPolicy, ProcessConfig, ProcessError, ProcessExit, ProcessStdin, RemoteExecution, Secret,
    TransportConfig, exec_cancellation,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(bun_ptr::ThreadSafeRefCounted)]
pub(crate) struct SSHConnection {
    hostname: Box<str>,
    port: u16,
    config: TransportConfig,
    session: std::sync::Mutex<Option<BlockingSession>>,
    close_requested: AtomicBool,
    next_operation_id: AtomicU64,
    operations: std::sync::Mutex<HashMap<u64, ExecCancelSender>>,
    ref_count: bun_ptr::ThreadSafeRefCount<SSHConnection>,
}

impl Drop for SSHConnection {
    fn drop(&mut self) {
        self.cancel_all_operations();
        let Some(session) = self
            .session
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        else {
            return;
        };
        let _ = session.close_with_timeout(std::time::Duration::ZERO);
    }
}

impl SSHConnection {
    pub(crate) fn constructor<'a>(
        heap: &JsHeap<'a>,
        hostname: &'a [u8],
        port: u16,
        username: &'a [u8],
        host_key_kind: &[u8],
        known_hosts: Vec<u8>,
        pins: Option<Vec<bun_core::Utf8Bytes<'static>>>,
        connect_timeout_ms: u64,
        max_channels: usize,
    ) -> bindgen::Result<'a, *mut Self> {
        let hostname = checked_utf8(heap, hostname, "hostname")?.into_owned();
        let username = checked_utf8(heap, username, "username")?.into_owned();
        let host_key = match host_key_kind {
            b"knownHosts" => HostKeyPolicy::KnownHosts(bun_ssh::KnownHostsSource::new(known_hosts)),
            b"pinned" => {
                let pins = pins
                    .ok_or_else(|| heap.type_error(format_args!("host key pins are required")))?;
                HostKeyPolicy::Pinned(
                    pins.iter()
                        .map(|pin| match std::str::from_utf8(pin.slice()) {
                            Ok(pin) => Ok(pin.to_string()),
                            Err(_) => {
                                Err(heap
                                    .type_error(format_args!("hostKey.sha256 must be valid UTF-8")))
                            }
                        })
                        .collect::<bindgen::Result<'a, _>>()?,
                )
            }
            _ => return Err(heap.type_error(format_args!("unsupported host key policy"))),
        };
        Ok(bun_core::heap::into_raw(Box::new(Self {
            hostname: hostname.clone().into_boxed_str(),
            port,
            config: TransportConfig {
                hostname,
                port,
                username,
                host_key,
                connect_timeout_ms,
                max_channels,
            },
            session: std::sync::Mutex::new(None),
            close_requested: AtomicBool::new(false),
            next_operation_id: AtomicU64::new(0),
            operations: std::sync::Mutex::new(HashMap::new()),
            ref_count: bun_ptr::ThreadSafeRefCount::init(),
        })))
    }

    pub(crate) fn finalize(&self) {}

    pub(crate) fn get_hostname(&self) -> &[u8] {
        self.hostname.as_bytes()
    }

    pub(crate) fn get_port(&self) -> u16 {
        self.port
    }

    pub(crate) fn connect_transport<'a>(
        &self,
        cx: &mut JsScope<'a>,
    ) -> bindgen::Result<'a, JSValue> {
        let (operation_id, cancel) = self.begin_operation();
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<ConnectJob>::schedule(
            &cx.js_thread(),
            ConnectJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                config: self.config.clone(),
                operation_id,
                cancel,
                result: None,
            },
            ConnectJs { promise },
        );
        Ok(value)
    }

    pub(crate) fn is_closed(&self, _cx: &mut JsScope<'_>) -> bool {
        self.session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map_or(true, BlockingSession::is_closed)
    }

    fn connect(
        &self,
        config: &TransportConfig,
        cancel: ExecCancelReceiver,
    ) -> Result<ConnectionInfo, ConnectError> {
        {
            let slot = self
                .session
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(session) = slot.as_ref() {
                return Ok(session.info());
            }
        }
        if self.close_requested.load(Ordering::Acquire) {
            return Err(ConnectError::Io("tcp", "connection was closed".into()));
        }
        if *cancel.borrow() {
            return Err(ConnectError::Aborted("handshake"));
        }

        let session = BlockingSession::connect_transport_with_cancel(config, cancel.clone())?;
        let info = session.info();
        if *cancel.borrow() {
            let _ = session.close_with_timeout(std::time::Duration::ZERO);
            return Err(ConnectError::Aborted("handshake"));
        }
        let mut slot = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.close_requested.load(Ordering::Acquire) {
            drop(slot);
            let _ = session.close_with_timeout(std::time::Duration::ZERO);
            return Err(ConnectError::Io("tcp", "connection was closed".into()));
        }
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.info());
        }
        *slot = Some(session);
        Ok(info)
    }

    fn authenticate(
        &self,
        auth: &Auth,
        timeout_ms: u64,
        cancel: ExecCancelReceiver,
    ) -> Result<(), AuthError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| AuthError::Protocol("SSH session is closed".into()))?;
        session.authenticate_with_cancel(auth, &self.config.username, timeout_ms, cancel)
    }

    fn close_session_with_cancel(
        &self,
        grace_period_ms: u64,
        cancel: ExecCancelReceiver,
    ) -> Result<CloseResult, CloseError> {
        self.close_session_optional_cancel(grace_period_ms, Some(cancel))
    }

    fn close_session_optional_cancel(
        &self,
        grace_period_ms: u64,
        cancel: Option<ExecCancelReceiver>,
    ) -> Result<CloseResult, CloseError> {
        self.close_requested.store(true, Ordering::Release);
        self.cancel_all_operations();
        let mut slot = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(session) = slot.take() else {
            return Ok(CloseResult { forced: false });
        };
        let grace_period = if cancel.as_ref().is_some_and(|cancel| *cancel.borrow()) {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_millis(grace_period_ms)
        };
        match cancel {
            Some(cancel) => session.close_with_timeout_cancel(grace_period, cancel),
            None => session.close_with_timeout(grace_period),
        }
    }

    fn begin_operation(&self) -> (u64, ExecCancelReceiver) {
        let id = self.next_operation_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = exec_cancellation();
        self.operations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(id, sender);
        (id, receiver)
    }

    fn finish_operation(&self, id: u64) {
        self.operations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&id);
    }

    fn request_cancel(&self, id: u64) -> bool {
        let operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(sender) = operations.get(&id) else {
            return false;
        };
        sender.send_replace(true);
        true
    }

    fn cancel_all_operations(&self) {
        for sender in self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
        {
            sender.send_replace(true);
        }
    }

    fn exec(
        &self,
        command: Vec<u8>,
        stdin: Vec<u8>,
        timeout_ms: u64,
        max_output_bytes: u64,
        cancel: ExecCancelReceiver,
    ) -> Result<ExecResult, ExecError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| ExecError::channel_closed("SSH session is not connected".to_string()))?;
        session.exec_with_cancel(
            command,
            stdin,
            (timeout_ms != 0).then(|| std::time::Duration::from_millis(timeout_ms)),
            max_output_bytes,
            cancel,
        )
    }

    fn start_process(
        &self,
        command: Vec<u8>,
        config: ProcessConfig,
        timeout_ms: u64,
        cancel: ExecCancelReceiver,
    ) -> Result<BlockingProcess, ExecError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| ExecError::channel_closed("SSH session is not connected".to_string()))?;
        session.start_process(
            command,
            config,
            (timeout_ms != 0).then(|| std::time::Duration::from_millis(timeout_ms)),
            cancel,
        )
    }

    pub(crate) fn execute<'a>(
        &self,
        cx: &mut JsScope<'a>,
        command: Vec<u8>,
        stdin: Vec<u8>,
        timeout_ms: u64,
        max_output_bytes: u64,
    ) -> bindgen::Result<'a, JSValue> {
        let (operation_id, cancel) = self.begin_operation();
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<ExecJob>::schedule(
            &cx.js_thread(),
            ExecJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                operation_id,
                command,
                stdin,
                timeout_ms,
                max_output_bytes,
                cancel,
                result: None,
            },
            promise,
        );

        let object = JSValue::create_empty_object(cx.global(), 2);
        object.put(
            cx.global(),
            b"id",
            JSValue::js_number_from_uint64(operation_id),
        );
        object.put(cx.global(), b"promise", value);
        Ok(object)
    }

    pub(crate) fn start_process_js<'a>(
        &self,
        cx: &mut JsScope<'a>,
        command: Vec<u8>,
        stdin_mode: &[u8],
        stdin_data: Vec<u8>,
        capture_stdout: bool,
        capture_stderr: bool,
        timeout_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        let stdin = match stdin_mode {
            b"ignore" => ProcessStdin::Ignore,
            b"pipe" => ProcessStdin::Pipe,
            b"data" => ProcessStdin::Data(stdin_data),
            _ => {
                return Err(cx
                    .heap
                    .type_error(format_args!("unsupported SSH stdin mode")));
            }
        };
        let config = ProcessConfig {
            stdin,
            capture_stdout,
            capture_stderr,
        };
        let (operation_id, cancel) = self.begin_operation();
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<StartProcessJob>::schedule(
            &cx.js_thread(),
            StartProcessJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                operation_id,
                command,
                config,
                timeout_ms,
                cancel,
                result: None,
            },
            promise,
        );

        let object = JSValue::create_empty_object(cx.global(), 2);
        object.put(
            cx.global(),
            b"id",
            JSValue::js_number_from_uint64(operation_id),
        );
        object.put(cx.global(), b"promise", value);
        Ok(object)
    }

    pub(crate) fn cancel_operation(&self, _cx: &mut JsScope<'_>, operation_id: u64) -> bool {
        self.request_cancel(operation_id)
    }

    pub(crate) fn authenticate_password<'a>(
        &self,
        cx: &mut JsScope<'a>,
        password: Vec<u8>,
        timeout_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule_auth(cx, Auth::Password(Secret::Bytes(password)), timeout_ms)
    }

    pub(crate) fn authenticate_private_key<'a>(
        &self,
        cx: &mut JsScope<'a>,
        key: Vec<u8>,
        timeout_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule_auth(
            cx,
            Auth::PrivateKey {
                key,
                passphrase: None,
            },
            timeout_ms,
        )
    }

    pub(crate) fn authenticate_private_key_with_passphrase<'a>(
        &self,
        cx: &mut JsScope<'a>,
        key: Vec<u8>,
        passphrase: Vec<u8>,
        timeout_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule_auth(
            cx,
            Auth::PrivateKey {
                key,
                passphrase: Some(Secret::Bytes(passphrase)),
            },
            timeout_ms,
        )
    }

    fn schedule_auth<'a>(
        &self,
        cx: &mut JsScope<'a>,
        auth: Auth,
        timeout_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        let (operation_id, cancel) = self.begin_operation();
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<AuthJob>::schedule(
            &cx.js_thread(),
            AuthJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                operation_id,
                auth: Some(auth),
                timeout_ms,
                cancel,
                result: None,
            },
            promise,
        );
        Ok(value)
    }

    pub(crate) fn close<'a>(
        &self,
        cx: &mut JsScope<'a>,
        grace_period_ms: u64,
    ) -> bindgen::Result<'a, JSValue> {
        let (cancel_sender, cancel) = exec_cancellation();
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<CloseJob>::schedule(
            &cx.js_thread(),
            CloseJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                grace_period_ms,
                cancel_sender,
                cancel,
                result: None,
            },
            promise,
        );
        Ok(value)
    }
}

#[derive(bun_ptr::ThreadSafeRefCounted)]
pub(crate) struct SSHSpawnProcess {
    process: BlockingProcess,
    connection: bun_ptr::RefPtr<SSHConnection>,
    operation_id: u64,
    ref_count: bun_ptr::ThreadSafeRefCount<SSHSpawnProcess>,
}

impl SSHSpawnProcess {
    fn new(
        process: BlockingProcess,
        connection: bun_ptr::RefPtr<SSHConnection>,
        operation_id: u64,
    ) -> Self {
        Self {
            process,
            connection,
            operation_id,
            ref_count: bun_ptr::ThreadSafeRefCount::init(),
        }
    }

    pub(crate) fn finalize(&self) {
        self.connection.finish_operation(self.operation_id);
    }

    fn finish_operation(&self) {
        self.connection.finish_operation(self.operation_id);
    }

    fn schedule<'a>(
        &self,
        cx: &mut JsScope<'a>,
        operation: ProcessOperation,
    ) -> bindgen::Result<'a, JSValue> {
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<ProcessJob>::schedule(
            &cx.js_thread(),
            ProcessJob {
                process: unsafe { bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut()) },
                operation,
                result: None,
            },
            promise,
        );
        Ok(value)
    }

    pub(crate) fn read_stdout<'a>(
        &self,
        cx: &mut JsScope<'a>,
        max_bytes: usize,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::ReadStdout(max_bytes))
    }

    pub(crate) fn read_stderr<'a>(
        &self,
        cx: &mut JsScope<'a>,
        max_bytes: usize,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::ReadStderr(max_bytes))
    }

    pub(crate) fn discard_stdout<'a>(&self, cx: &mut JsScope<'a>) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::DiscardStdout)
    }

    pub(crate) fn discard_stderr<'a>(&self, cx: &mut JsScope<'a>) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::DiscardStderr)
    }

    pub(crate) fn write_stdin<'a>(
        &self,
        cx: &mut JsScope<'a>,
        data: Vec<u8>,
    ) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::WriteStdin(data))
    }

    pub(crate) fn close_stdin<'a>(&self, cx: &mut JsScope<'a>) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::CloseStdin)
    }

    pub(crate) fn send_signal<'a>(
        &self,
        cx: &mut JsScope<'a>,
        signal: &[u8],
    ) -> bindgen::Result<'a, JSValue> {
        let signal = std::str::from_utf8(signal)
            .map_err(|_| {
                cx.heap
                    .type_error(format_args!("SSH signal must be valid UTF-8"))
            })?
            .to_string();
        self.schedule(cx, ProcessOperation::SendSignal(signal))
    }

    pub(crate) fn cancel(&self, _cx: &mut JsScope<'_>) -> bool {
        self.process.cancel()
    }

    pub(crate) fn wait_exit<'a>(&self, cx: &mut JsScope<'a>) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::WaitExit)
    }

    pub(crate) fn wait_closed<'a>(&self, cx: &mut JsScope<'a>) -> bindgen::Result<'a, JSValue> {
        self.schedule(cx, ProcessOperation::WaitClosed)
    }

    pub(crate) fn get_remote_execution(&self) -> &[u8] {
        remote_execution_name(self.process.remote_execution())
    }
}

enum ProcessOperation {
    ReadStdout(usize),
    ReadStderr(usize),
    DiscardStdout,
    DiscardStderr,
    WriteStdin(Vec<u8>),
    CloseStdin,
    SendSignal(String),
    WaitExit,
    WaitClosed,
}

enum ProcessResult {
    Bytes(Option<Vec<u8>>),
    Exit(ProcessExit),
    Unit,
}

struct ProcessJob {
    process: bun_ptr::RefPtr<SSHSpawnProcess>,
    operation: ProcessOperation,
    result: Option<Result<ProcessResult, ProcessError>>,
}

// SAFETY: the process handle owns only thread-safe channel state, and its ref
// keeps that state alive while the job runs.
unsafe impl Send for ProcessJob {}

impl JobContext for ProcessJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        let process = &this.process.process;
        this.result = Some(match &this.operation {
            ProcessOperation::ReadStdout(max_bytes) => {
                process.read_stdout(*max_bytes).map(ProcessResult::Bytes)
            }
            ProcessOperation::ReadStderr(max_bytes) => {
                process.read_stderr(*max_bytes).map(ProcessResult::Bytes)
            }
            ProcessOperation::DiscardStdout => {
                process.discard_stdout();
                Ok(ProcessResult::Unit)
            }
            ProcessOperation::DiscardStderr => {
                process.discard_stderr();
                Ok(ProcessResult::Unit)
            }
            ProcessOperation::WriteStdin(data) => process
                .write_stdin(data.clone())
                .map(|()| ProcessResult::Unit),
            ProcessOperation::CloseStdin => process.close_stdin().map(|()| ProcessResult::Unit),
            ProcessOperation::SendSignal(signal) => {
                process.send_signal(signal).map(|()| ProcessResult::Unit)
            }
            ProcessOperation::WaitExit => process.wait_exit().map(ProcessResult::Exit),
            ProcessOperation::WaitClosed => {
                process.wait_closed();
                Ok(ProcessResult::Unit)
            }
        });
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: the live off-thread half remains valid for the duration of
        // this call, and BlockingProcess::cancel only touches thread-safe state.
        let job = unsafe { &*off };
        job.process.process.cancel();
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
        let global = cx.global();
        if matches!(this.operation, ProcessOperation::WaitClosed) {
            this.process.finish_operation();
        }
        match this.result.take().expect("process result") {
            Ok(ProcessResult::Bytes(Some(bytes))) => promise.resolve(
                global,
                JSValue::create_buffer_from_box(global, bytes.into_boxed_slice())?,
            ),
            Ok(ProcessResult::Bytes(None) | ProcessResult::Unit) => {
                promise.resolve(global, JSValue::UNDEFINED)
            }
            Ok(ProcessResult::Exit(exit)) => {
                let value = JSValue::create_empty_object(global, 2);
                value.put(global, b"status", exit_status_to_js(global, &exit.status)?);
                value.put(
                    global,
                    b"remoteExecution",
                    remote_execution_to_js(global, exit.remote_execution)?,
                );
                promise.resolve(global, value)
            }
            Err(error) => {
                let error = process_error_to_js(global, error)?;
                promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

struct ConnectJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    config: TransportConfig,
    operation_id: u64,
    cancel: ExecCancelReceiver,
    result: Option<Result<ConnectionInfo, ConnectError>>,
}

struct ExecJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    operation_id: u64,
    command: Vec<u8>,
    stdin: Vec<u8>,
    timeout_ms: u64,
    max_output_bytes: u64,
    cancel: ExecCancelReceiver,
    result: Option<Result<ExecResult, ExecError>>,
}

struct StartProcessJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    operation_id: u64,
    command: Vec<u8>,
    config: ProcessConfig,
    timeout_ms: u64,
    cancel: ExecCancelReceiver,
    result: Option<Result<BlockingProcess, ExecError>>,
}

// SAFETY: every field is owned or thread-safe. The connection ref keeps the
// transport alive while the channel is opened and exec is acknowledged.
unsafe impl Send for StartProcessJob {}

impl JobContext for StartProcessJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(this.connection.start_process(
            std::mem::take(&mut this.command),
            this.config.clone(),
            this.timeout_ms,
            this.cancel.clone(),
        ));
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: the connection ref keeps the shared cancellation map alive,
        // and request_cancel only touches thread-safe state.
        let job = unsafe { &*off };
        job.connection.request_cancel(job.operation_id);
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
        let global = cx.global();
        match this.result.take().expect("start process result") {
            Ok(process) => {
                let ptr = bun_core::heap::into_raw(Box::new(SSHSpawnProcess::new(
                    process,
                    this.connection,
                    this.operation_id,
                )));
                let value = unsafe { SSHSpawnProcess::to_js_ptr(ptr, global) };
                promise.resolve(global, value)
            }
            Err(error) => {
                this.connection.finish_operation(this.operation_id);
                let error = exec_error_to_js(global, error)?;
                promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

// SAFETY: every field is owned or thread-safe. The ref keeps the connection
// payload alive while the channel operation runs.
unsafe impl Send for ExecJob {}

impl JobContext for ExecJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(this.connection.exec(
            std::mem::take(&mut this.command),
            std::mem::take(&mut this.stdin),
            this.timeout_ms,
            this.max_output_bytes,
            this.cancel.clone(),
        ));
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: the connection ref keeps the shared cancellation map alive,
        // and request_cancel only touches thread-safe state.
        let job = unsafe { &*off };
        job.connection.request_cancel(job.operation_id);
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
        this.connection.finish_operation(this.operation_id);
        let global = cx.global();
        match this.result.take().expect("exec result") {
            Ok(result) => promise.resolve(global, exec_result_to_js(global, result)?),
            Err(error) => {
                let error = exec_error_to_js(global, error)?;
                promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

// SAFETY: every field is owned or thread-safe. The ref keeps the connection
// payload alive while the job is off the JS thread.
unsafe impl Send for ConnectJob {}

#[derive(JsAffine)]
struct ConnectJs {
    promise: JSPromiseStrong,
}

impl JobContext for ConnectJob {
    type OffThread = Self;
    type Js = ConnectJs;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(this.connection.connect(&this.config, this.cancel.clone()));
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: the connection ref keeps the shared cancellation map alive,
        // and request_cancel only touches thread-safe state.
        let job = unsafe { &*off };
        job.connection.request_cancel(job.operation_id);
    }

    fn then(mut this: Self, mut js: ConnectJs, cx: &bun_jsc::JsThread<'_>) -> JsResult<()> {
        this.connection.finish_operation(this.operation_id);
        let global = cx.global();
        match this.result.take().expect("connect result") {
            Ok(info) => js
                .promise
                .resolve(global, connection_info_to_js(global, &info)?),
            Err(error) => {
                let error = native_error(global, error.to_string(), error.code(), error.phase())?;
                js.promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

struct AuthJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    operation_id: u64,
    auth: Option<Auth>,
    timeout_ms: u64,
    cancel: ExecCancelReceiver,
    result: Option<Result<(), AuthError>>,
}

// SAFETY: the authentication payload is owned and the ref keeps the
// thread-safe connection alive while the job runs.
unsafe impl Send for AuthJob {}

impl JobContext for AuthJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        let auth = this.auth.take().expect("authentication request");
        this.result = Some(this.connection.authenticate(
            &auth,
            this.timeout_ms,
            this.cancel.clone(),
        ));
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: the connection ref keeps the shared cancellation map alive,
        // and request_cancel only touches thread-safe state.
        let job = unsafe { &*off };
        job.connection.request_cancel(job.operation_id);
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
        this.connection.finish_operation(this.operation_id);
        let global = cx.global();
        match this.result.take().expect("authentication result") {
            Ok(()) => promise.resolve(global, JSValue::UNDEFINED),
            Err(error) => {
                let error = native_error(global, error.to_string(), error.code(), error.phase())?;
                promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

struct CloseJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    grace_period_ms: u64,
    cancel_sender: ExecCancelSender,
    cancel: ExecCancelReceiver,
    result: Option<Result<CloseResult, CloseError>>,
}

// SAFETY: every field is owned or thread-safe. The ref keeps the connection
// payload alive while close runs.
unsafe impl Send for CloseJob {}

impl JobContext for CloseJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;
    const CANCELLABLE: bool = true;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(
            this.connection
                .close_session_with_cancel(this.grace_period_ms, this.cancel.clone()),
        );
        Some(done)
    }

    unsafe fn cancel(off: *mut Self::OffThread) {
        // SAFETY: watch::Sender is thread-safe and request_cancel only touches
        // thread-safe state.
        let job = unsafe { &*off };
        job.cancel_sender.send_replace(true);
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
        let global = cx.global();
        match this.result.take().expect("close result") {
            Ok(result) => {
                let value = JSValue::create_empty_object(global, 1);
                value.put(global, b"forced", JSValue::js_boolean(result.forced));
                promise.resolve(global, value)
            }
            Err(error) => {
                let error = native_error(global, error.to_string(), error.code(), error.phase())?;
                promise.reject_with_async_stack(global, Ok(error))
            }
        }
    }
}

fn connection_info_to_js(global: &JSGlobalObject, info: &ConnectionInfo) -> JsResult<JSValue> {
    let object = JSValue::create_empty_object(global, 7);
    object.put(
        global,
        b"hostname",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, info.hostname.as_bytes())?,
    );
    object.put(
        global,
        b"port",
        JSValue::js_number_from_int32(i32::from(info.port)),
    );
    object.put(
        global,
        b"username",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, info.username.as_bytes())?,
    );
    object.put(
        global,
        b"hostKeyAlgorithm",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, info.host_key_algorithm.as_bytes())?,
    );
    object.put(
        global,
        b"hostKeySHA256",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, info.host_key_sha256.as_bytes())?,
    );
    object.put(
        global,
        b"cipherClientToServer",
        bun_jsc::bun_string_jsc::create_utf8_for_js(
            global,
            info.cipher_client_to_server.as_bytes(),
        )?,
    );
    object.put(
        global,
        b"cipherServerToClient",
        bun_jsc::bun_string_jsc::create_utf8_for_js(
            global,
            info.cipher_server_to_client.as_bytes(),
        )?,
    );
    Ok(object)
}

fn exec_result_to_js(global: &JSGlobalObject, result: ExecResult) -> JsResult<JSValue> {
    let object = JSValue::create_empty_object(global, 5);
    object.put(
        global,
        b"stdout",
        JSValue::create_buffer_from_box(global, result.stdout.into_boxed_slice())?,
    );
    object.put(
        global,
        b"stderr",
        JSValue::create_buffer_from_box(global, result.stderr.into_boxed_slice())?,
    );
    object.put(
        global,
        b"status",
        exit_status_to_js(global, &result.exit_status)?,
    );
    object.put(
        global,
        b"exitCode",
        exit_status_code_to_js(&result.exit_status),
    );
    object.put(
        global,
        b"remoteExecution",
        remote_execution_to_js(global, result.remote_execution)?,
    );
    Ok(object)
}

fn exec_error_to_js(global: &JSGlobalObject, error: ExecError) -> JsResult<JSValue> {
    let value = native_error(global, error.to_string(), error.code(), error.phase())?;
    value.put(
        global,
        b"status",
        exit_status_to_js(global, &error.exit_status)?,
    );
    value.put(
        global,
        b"exitCode",
        exit_status_code_to_js(&error.exit_status),
    );
    value.put(
        global,
        b"stdout",
        JSValue::create_buffer_from_box(global, error.stdout.into_boxed_slice())?,
    );
    value.put(
        global,
        b"stderr",
        JSValue::create_buffer_from_box(global, error.stderr.into_boxed_slice())?,
    );
    value.put(
        global,
        b"remoteExecution",
        remote_execution_to_js(global, error.remote_execution)?,
    );
    Ok(value)
}

fn process_error_to_js(global: &JSGlobalObject, error: ProcessError) -> JsResult<JSValue> {
    let value = native_error(global, error.to_string(), error.code(), error.phase())?;
    value.put(
        global,
        b"remoteExecution",
        remote_execution_to_js(global, error.remote_execution())?,
    );
    Ok(value)
}

fn exit_status_to_js(global: &JSGlobalObject, status: &ExitStatus) -> JsResult<JSValue> {
    let object = JSValue::create_empty_object(global, 4);
    match status {
        ExitStatus::Exit { code } => {
            object.put(
                global,
                b"type",
                bun_jsc::bun_string_jsc::create_utf8_for_js(global, b"exit")?,
            );
            object.put(
                global,
                b"code",
                JSValue::js_number_from_uint64(u64::from(*code)),
            );
        }
        ExitStatus::Signal {
            signal,
            core_dumped,
        } => {
            object.put(
                global,
                b"type",
                bun_jsc::bun_string_jsc::create_utf8_for_js(global, b"signal")?,
            );
            object.put(
                global,
                b"signal",
                bun_jsc::bun_string_jsc::create_utf8_for_js(global, signal.as_bytes())?,
            );
            object.put(global, b"coreDumped", JSValue::js_boolean(*core_dumped));
        }
        ExitStatus::Unknown => {
            object.put(
                global,
                b"type",
                bun_jsc::bun_string_jsc::create_utf8_for_js(global, b"unknown")?,
            );
        }
    }
    Ok(object)
}

fn exit_status_code_to_js(status: &ExitStatus) -> JSValue {
    match status {
        ExitStatus::Exit { code } => JSValue::js_number_from_uint64(u64::from(*code)),
        ExitStatus::Signal { .. } | ExitStatus::Unknown => JSValue::NULL,
    }
}

fn remote_execution_to_js(
    global: &JSGlobalObject,
    remote_execution: RemoteExecution,
) -> JsResult<JSValue> {
    bun_jsc::bun_string_jsc::create_utf8_for_js(global, remote_execution_name(remote_execution))
}

fn remote_execution_name(remote_execution: RemoteExecution) -> &'static [u8] {
    match remote_execution {
        RemoteExecution::NotStarted => b"not-started",
        RemoteExecution::MayHaveStarted => b"may-have-started",
        RemoteExecution::ExitObserved => b"exit-observed",
    }
}

fn native_error(
    global: &JSGlobalObject,
    message: impl core::fmt::Display,
    code: &str,
    phase: &str,
) -> JsResult<JSValue> {
    let error = global.create_error_instance(format_args!("{message}"));
    error.put(
        global,
        b"code",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, code.as_bytes())?,
    );
    error.put(
        global,
        b"phase",
        bun_jsc::bun_string_jsc::create_utf8_for_js(global, phase.as_bytes())?,
    );
    Ok(error)
}

fn checked_utf8<'a>(
    heap: &JsHeap<'a>,
    bytes: &'a [u8],
    name: &'static str,
) -> bindgen::Result<'a, std::borrow::Cow<'a, str>> {
    std::str::from_utf8(bytes)
        .map(std::borrow::Cow::Borrowed)
        .map_err(|_| heap.type_error(format_args!("{name} must be valid UTF-8")))
}
