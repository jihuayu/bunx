use bun_jsc::bindgen::{self, JsHeap, JsScope};
use bun_jsc::{JSGlobalObject, JSPromiseStrong, JSValue, Job, JobContext, JsAffine, JsResult};
use bun_ssh::{
    Auth, AuthError, BlockingSession, CloseError, CloseResult, ConnectError, ConnectionInfo,
    ExecCancelReceiver, ExecCancelSender, ExecError, ExecResult, ExitStatus, HostKeyPolicy,
    RemoteExecution, Secret, TransportConfig, exec_cancellation,
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
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<ConnectJob>::schedule(
            &cx.js_thread(),
            ConnectJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                config: self.config.clone(),
                result: None,
            },
            ConnectJs { promise },
        );
        Ok(value)
    }

    fn connect(&self, config: &TransportConfig) -> Result<ConnectionInfo, ConnectError> {
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
            return Err(ConnectError::Io("connection was closed".into()));
        }

        let session = BlockingSession::connect_transport(config)?;
        let info = session.info();
        let mut slot = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.close_requested.load(Ordering::Acquire) {
            drop(slot);
            let _ = session.close_with_timeout(std::time::Duration::ZERO);
            return Err(ConnectError::Io("connection was closed".into()));
        }
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.info());
        }
        *slot = Some(session);
        Ok(info)
    }

    fn authenticate(&self, auth: &Auth, timeout_ms: u64) -> Result<(), AuthError> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| AuthError::Protocol("SSH session is closed".into()))?;
        session.authenticate_with(auth, &self.config.username, timeout_ms)
    }

    fn close_session(&self, grace_period_ms: u64) -> Result<CloseResult, CloseError> {
        self.close_requested.store(true, Ordering::Release);
        self.cancel_all_operations();
        let mut slot = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(session) = slot.take() else {
            return Ok(CloseResult { forced: false });
        };
        session.close_with_timeout(std::time::Duration::from_millis(grace_period_ms))
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
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<AuthJob>::schedule(
            &cx.js_thread(),
            AuthJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                auth: Some(auth),
                timeout_ms,
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
        let promise = JSPromiseStrong::init(cx.global());
        let value = promise.value();
        Job::<CloseJob>::schedule(
            &cx.js_thread(),
            CloseJob {
                connection: unsafe {
                    bun_ptr::RefPtr::init_ref(std::ptr::from_ref(self).cast_mut())
                },
                grace_period_ms,
                result: None,
            },
            promise,
        );
        Ok(value)
    }
}

struct ConnectJob {
    connection: bun_ptr::RefPtr<SSHConnection>,
    config: TransportConfig,
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

// SAFETY: every field is owned or thread-safe. The ref keeps the connection
// payload alive while the channel operation runs.
unsafe impl Send for ExecJob {}

impl JobContext for ExecJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;

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

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(this.connection.connect(&this.config));
        Some(done)
    }

    fn then(mut this: Self, mut js: ConnectJs, cx: &bun_jsc::JsThread<'_>) -> JsResult<()> {
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
    auth: Option<Auth>,
    timeout_ms: u64,
    result: Option<Result<(), AuthError>>,
}

// SAFETY: the authentication payload is owned and the ref keeps the
// thread-safe connection alive while the job runs.
unsafe impl Send for AuthJob {}

impl JobContext for AuthJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        let auth = this.auth.take().expect("authentication request");
        this.result = Some(this.connection.authenticate(&auth, this.timeout_ms));
        Some(done)
    }

    fn then(
        mut this: Self,
        mut promise: JSPromiseStrong,
        cx: &bun_jsc::JsThread<'_>,
    ) -> JsResult<()> {
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
    result: Option<Result<CloseResult, CloseError>>,
}

// SAFETY: every field is owned or thread-safe. The ref keeps the connection
// payload alive while close runs.
unsafe impl Send for CloseJob {}

impl JobContext for CloseJob {
    type OffThread = Self;
    type Js = JSPromiseStrong;

    fn run(this: &mut Self, done: bun_jsc::Completion<Self>) -> Option<bun_jsc::Completion<Self>> {
        this.result = Some(this.connection.close_session(this.grace_period_ms));
        Some(done)
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
    let value = match remote_execution {
        RemoteExecution::NotStarted => b"not-started".as_slice(),
        RemoteExecution::MayHaveStarted => b"may-have-started".as_slice(),
        RemoteExecution::ExitObserved => b"exit-observed".as_slice(),
    };
    bun_jsc::bun_string_jsc::create_utf8_for_js(global, value)
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
