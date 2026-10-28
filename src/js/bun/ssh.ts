const ArrayIsArray = Array.isArray;
const ObjectFreeze = Object.freeze;
const ObjectHasOwn = Object.hasOwn;
const ObjectKeys = Object.keys;
const ObjectCreate = Object.create;
const ObjectAssign = Object.assign;
const NumberIsSafeInteger = Number.isSafeInteger;
const defineProperty = Object.defineProperty;

const DEFAULT_PORT = 22;
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_AUTHENTICATION_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_CHANNELS = 8;
const DEFAULT_MAX_PENDING_OPERATIONS = 64;
const DEFAULT_QUEUE_TIMEOUT_MS = 30_000;
const DEFAULT_CLOSE_GRACE_PERIOD_MS = 5_000;
const DEFAULT_EXEC_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const SHA256_PREFIX = "SHA256:";
const MAX_KNOWN_HOSTS_BYTES = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const MAX_COMMAND_BYTES = 64 * 1024;
const MAX_EXEC_INPUT_BYTES = 32 * 1024 * 1024;
const EMPTY_BYTES = new Uint8Array();
const NativeSSHConnection = $bindgen("ssh_jsc.bind.ts", "SSHConnection");
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const AUTH_TIMEOUT = Symbol("SSH authentication timeout");

const configObjectKeys = [
  "hostname",
  "port",
  "username",
  "hostKey",
  "auth",
  "connectTimeoutMs",
  "authenticationTimeoutMs",
  "maxChannels",
  "maxPendingOperations",
  "queueTimeoutMs",
];
const hostKeyKeys = ["type", "file", "sha256"];
const authKeys = ["type", "password", "key", "passphrase"];
const connectKeys = ["signal"];
const closeKeys = ["force", "gracePeriodMs"];
const execKeys = ["signal", "timeoutMs", "stdin", "check", "maxOutputBytes"];

class SSHError extends Error {
  constructor(
    message: string,
    options: {
      code: string;
      phase: string;
      cause?: unknown;
      operationId?: string;
      remoteExecution?: string;
      status?: object;
      stdout?: Uint8Array;
      stderr?: Uint8Array;
    },
  ) {
    super(message);
    this.name = "SSHError";
    defineProperty(this, "code", { value: options.code, enumerable: true });
    defineProperty(this, "phase", { value: options.phase, enumerable: true });
    defineProperty(this, "operationId", { value: options.operationId ?? "", enumerable: true });
    defineProperty(this, "remoteExecution", {
      value: options.remoteExecution ?? "not-started",
      enumerable: true,
    });
    if (options.status !== undefined) {
      defineProperty(this, "status", { value: options.status, enumerable: true });
    }
    if (options.stdout !== undefined) {
      defineProperty(this, "stdout", { value: options.stdout, enumerable: true });
    }
    if (options.stderr !== undefined) {
      defineProperty(this, "stderr", { value: options.stderr, enumerable: true });
    }
    if (options.cause !== undefined) {
      defineProperty(this, "cause", { value: options.cause, enumerable: false });
    }
  }
}

ObjectFreeze(SSHError.prototype);

function configError(message: string): never {
  throw new SSHError(message, { code: "ERR_SSH_CONFIG", phase: "config" });
}

function runtimeError(message: string, code: string, phase: string, cause?: unknown): SSHError {
  return new SSHError(message, { code, phase, cause });
}

function abortError(signal: AbortSignal, phase: string): SSHError {
  const reason = signal.reason;
  if (reason instanceof SSHError) {
    return reason;
  }
  if (reason === AUTH_TIMEOUT) {
    return runtimeError("SSH authentication timed out", "ERR_SSH_AUTH_TIMEOUT", "auth");
  }
  return runtimeError("SSH operation was aborted", "ERR_SSH_ABORTED", phase, reason);
}

function normalizeError(error: unknown, fallbackCode: string, fallbackPhase: string): SSHError {
  if (error instanceof SSHError) {
    return error;
  }

  if ($isObject(error)) {
    const code = (error as { code?: unknown }).code;
    const phase = (error as { phase?: unknown }).phase;
    if (typeof code === "string" && typeof phase === "string") {
      const message =
        typeof (error as { message?: unknown }).message === "string"
          ? (error as { message: string }).message
          : "Bun.SSH operation failed";
      const native = error as {
        operationId?: unknown;
        remoteExecution?: unknown;
        status?: unknown;
        stdout?: unknown;
        stderr?: unknown;
      };
      return new SSHError(message, {
        code,
        phase,
        cause: error,
        operationId: typeof native.operationId === "string" ? native.operationId : undefined,
        remoteExecution:
          native.remoteExecution === "may-have-started" ||
          native.remoteExecution === "exit-observed" ||
          native.remoteExecution === "not-started"
            ? native.remoteExecution
            : undefined,
        status: snapshotExitStatus(native.status),
        stdout: native.stdout instanceof Uint8Array ? copyErrorBytes(native.stdout) : undefined,
        stderr: native.stderr instanceof Uint8Array ? copyErrorBytes(native.stderr) : undefined,
      });
    }
  }

  return runtimeError("Bun.SSH operation failed", fallbackCode, fallbackPhase, error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return $isObject(value) && !ArrayIsArray(value);
}

function copyErrorBytes(value: Uint8Array): Uint8Array {
  try {
    return new Uint8Array(value);
  } catch {
    return EMPTY_BYTES;
  }
}

function snapshotExitStatus(value: unknown): object | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (value.type === "exit" && NumberIsSafeInteger(value.code) && value.code >= 0 && value.code <= 0xffff_ffff) {
    return ObjectFreeze({ type: "exit", code: value.code });
  }
  if (value.type === "signal" && typeof value.signal === "string" && typeof value.coreDumped === "boolean") {
    return ObjectFreeze({
      type: "signal",
      signal: value.signal,
      coreDumped: value.coreDumped,
    });
  }
  if (value.type === "unknown") {
    return ObjectFreeze({ type: "unknown" });
  }
  return undefined;
}

function rejectUnknownKeys(value: Record<string, unknown>, path: string, allowedKeys: string[]) {
  const keys = ObjectKeys(value);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (allowedKeys.indexOf(key) === -1) {
      configError(`SSH option ${JSON.stringify(path ? `${path}.${key}` : key)} is not supported`);
    }
  }
}

function requireRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) {
    configError(`SSH option "${path}" must be an object`);
  }
  return value;
}

function ownValue(value: Record<string, unknown>, path: string, key: string): unknown {
  if (!ObjectHasOwn(value, key)) {
    return undefined;
  }
  return value[key];
}

function snapshotRecord<T extends object>(value: T): T {
  return ObjectFreeze(ObjectAssign(ObjectCreate(null), value));
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0 || value.indexOf("\0") !== -1) {
    configError(`SSH option "${path}" must be a non-empty string without NUL characters`);
  }
  return value;
}

function optionalPositiveSafeInteger(
  value: unknown,
  path: string,
  defaultValue: number,
  min = 1,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (value === undefined) {
    return defaultValue;
  }
  if (!NumberIsSafeInteger(value) || (value as number) < min || (value as number) > max) {
    configError(`SSH option "${path}" must be a safe integer from ${min} to ${max}`);
  }
  return value as number;
}

function optionalNonNegativeSafeInteger(value: unknown, path: string, defaultValue: number): number {
  if (value === undefined) {
    return defaultValue;
  }
  if (!NumberIsSafeInteger(value) || (value as number) < 0) {
    configError(`SSH option "${path}" must be a non-negative safe integer`);
  }
  return value as number;
}

function copyBytes(value: Uint8Array, path: string): Uint8Array {
  try {
    return new Uint8Array(value);
  } catch {
    configError(`SSH option "${path}" must be a valid Uint8Array`);
  }
}

function snapshotSecret(value: unknown, path: string): string | Uint8Array | Function {
  if (typeof value === "function" || typeof value === "string") {
    return value;
  }
  if (value instanceof Uint8Array) {
    return copyBytes(value, path);
  }
  configError(`SSH option "${path}" must be a string, Uint8Array, or function`);
}

function snapshotPrivateKey(value: unknown, path: string): Uint8Array | Blob | Function {
  if (typeof value === "function" || value instanceof Blob) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return copyBytes(value, path);
  }
  configError(`SSH option "${path}" must be a Uint8Array, Blob, or function`);
}

function snapshotHostKey(value: unknown) {
  const hostKey = requireRecord(value, "hostKey");
  rejectUnknownKeys(hostKey, "hostKey", hostKeyKeys);
  const type = ownValue(hostKey, "hostKey", "type");

  if (type === "knownHosts") {
    const file = ownValue(hostKey, "hostKey", "file");
    if (!(file instanceof Blob)) {
      configError('SSH option "hostKey.file" must be a Blob');
    }
    return snapshotRecord({ type, file } as const);
  }

  if (type === "pinned") {
    const sha256 = ownValue(hostKey, "hostKey", "sha256");
    if (!ArrayIsArray(sha256) || sha256.length === 0) {
      configError('SSH option "hostKey.sha256" must be a non-empty array of strings');
    }

    const pins = new Array(sha256.length);
    for (let i = 0; i < sha256.length; i++) {
      const pin = sha256[i];
      if (typeof pin !== "string" || !pin.startsWith(SHA256_PREFIX) || pin.length === SHA256_PREFIX.length) {
        configError('SSH option "hostKey.sha256" must contain SHA256: fingerprints');
      }
      pins[i] = pin;
    }
    return snapshotRecord({ type, sha256: ObjectFreeze(pins) } as const);
  }

  configError('SSH option "hostKey.type" must be "knownHosts" or "pinned"');
}

function snapshotAuth(value: unknown) {
  const auth = requireRecord(value, "auth");
  rejectUnknownKeys(auth, "auth", authKeys);
  const type = ownValue(auth, "auth", "type");

  if (type === "password") {
    const password = ownValue(auth, "auth", "password");
    if (password === undefined) {
      configError('SSH option "auth.password" is required for password authentication');
    }
    return snapshotRecord({ type, password: snapshotSecret(password, "auth.password") } as const);
  }

  if (type === "privateKey") {
    const key = ownValue(auth, "auth", "key");
    if (key === undefined) {
      configError('SSH option "auth.key" is required for private key authentication');
    }

    const passphraseValue = ownValue(auth, "auth", "passphrase");
    const passphrase = passphraseValue === undefined ? undefined : snapshotSecret(passphraseValue, "auth.passphrase");
    const snapshot: {
      type: "privateKey";
      key: Uint8Array | Blob | Function;
      passphrase?: string | Uint8Array | Function;
    } = {
      type,
      key: snapshotPrivateKey(key, "auth.key"),
    };
    if (passphrase !== undefined) {
      snapshot.passphrase = passphrase;
    }
    return snapshotRecord(snapshot);
  }

  configError('SSH option "auth.type" must be "password" or "privateKey"');
}

function snapshotConnectOptions(value: unknown): AbortSignal | undefined {
  if (value === undefined) {
    return undefined;
  }
  const options = requireRecord(value, "connect options");
  rejectUnknownKeys(options, "", connectKeys);
  const signal = ownValue(options, "", "signal");
  if (signal === undefined) {
    return undefined;
  }
  if (!(signal instanceof AbortSignal)) {
    configError('SSH option "signal" must be an AbortSignal');
  }
  return signal;
}

function snapshotCloseOptions(value: unknown) {
  if (value === undefined) {
    return { force: false, gracePeriodMs: DEFAULT_CLOSE_GRACE_PERIOD_MS };
  }
  const options = requireRecord(value, "close options");
  rejectUnknownKeys(options, "", closeKeys);
  const force = ownValue(options, "", "force");
  if (force !== undefined && typeof force !== "boolean") {
    configError('SSH option "force" must be a boolean');
  }
  const gracePeriodMs = optionalNonNegativeSafeInteger(
    ownValue(options, "", "gracePeriodMs"),
    "gracePeriodMs",
    DEFAULT_CLOSE_GRACE_PERIOD_MS,
  );
  return ObjectFreeze({
    force: force === true,
    gracePeriodMs: force === true ? 0 : gracePeriodMs,
  });
}

function snapshotCommand(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    configError('SSH option "command" must be a non-empty string');
  }
  if (value.indexOf("\0") !== -1) {
    configError('SSH option "command" must not contain NUL characters');
  }
  const bytes = textEncoder.encode(value);
  if (bytes.byteLength > MAX_COMMAND_BYTES) {
    throw runtimeError(`SSH command exceeds the ${MAX_COMMAND_BYTES}-byte limit`, "ERR_SSH_RESOURCE_LIMIT", "config");
  }
  return bytes;
}

function snapshotExecOptions(value: unknown) {
  if (value === undefined) {
    value = {};
  }
  const options = requireRecord(value, "exec options");
  rejectUnknownKeys(options, "", execKeys);

  const signal = ownValue(options, "", "signal");
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    configError('SSH option "signal" must be an AbortSignal');
  }

  const timeoutMs = optionalNonNegativeSafeInteger(
    ownValue(options, "", "timeoutMs"),
    "timeoutMs",
    DEFAULT_EXEC_TIMEOUT_MS,
  );
  const maxOutputBytes = optionalNonNegativeSafeInteger(
    ownValue(options, "", "maxOutputBytes"),
    "maxOutputBytes",
    DEFAULT_MAX_OUTPUT_BYTES,
  );
  const checkValue = ownValue(options, "", "check");
  if (checkValue !== undefined && typeof checkValue !== "boolean") {
    configError('SSH option "check" must be a boolean');
  }

  const stdin = ownValue(options, "", "stdin");
  if (
    stdin !== undefined &&
    typeof stdin !== "string" &&
    !(stdin instanceof Uint8Array) &&
    !(stdin instanceof ArrayBuffer) &&
    !(stdin instanceof Blob) &&
    !(stdin instanceof ReadableStream)
  ) {
    configError('SSH option "stdin" must be a string, Uint8Array, ArrayBuffer, Blob, or ReadableStream');
  }

  return ObjectFreeze({
    signal,
    timeoutMs,
    maxOutputBytes,
    check: checkValue === true,
    stdin,
  });
}

function withAbort<T>(promise: PromiseLike<T> | T, signal: AbortSignal, phase: () => string): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(abortError(signal, phase()));
  }

  return new Promise((resolve, reject) => {
    function cleanup() {
      signal.removeEventListener("abort", onAbort);
    }
    function onAbort() {
      cleanup();
      reject(abortError(signal, phase()));
    }
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(promise).then(
      value => {
        cleanup();
        if (signal.aborted) {
          reject(abortError(signal, phase()));
        } else {
          resolve(value);
        }
      },
      error => {
        cleanup();
        reject(error);
      },
    );
  });
}

function copyRuntimeBytes(value: Uint8Array, path: string, phase: string): Uint8Array {
  try {
    return new Uint8Array(value);
  } catch (cause) {
    throw runtimeError(`${path} must be a valid Uint8Array`, "ERR_SSH_AUTH", phase, cause);
  }
}

async function readBlob(
  blob: Blob,
  path: string,
  maxBytes: number,
  phase: string,
  signal: AbortSignal,
): Promise<Uint8Array> {
  if (blob.size > maxBytes) {
    throw runtimeError(`${path} exceeds the ${maxBytes}-byte limit`, "ERR_SSH_RESOURCE_LIMIT", phase);
  }
  let bytes;
  try {
    bytes = await withAbort(blob.bytes(), signal, () => phase);
  } catch (cause) {
    if (cause instanceof SSHError) {
      throw cause;
    }
    throw runtimeError(`failed to read ${path}`, "ERR_SSH_IO", phase, cause);
  }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > maxBytes) {
    throw runtimeError(`${path} exceeds the ${maxBytes}-byte limit`, "ERR_SSH_RESOURCE_LIMIT", phase);
  }
  return copyRuntimeBytes(bytes, path, phase);
}

function checkExecInputSize(size: number): void {
  if (size > MAX_EXEC_INPUT_BYTES) {
    throw runtimeError(`SSH stdin exceeds the ${MAX_EXEC_INPUT_BYTES}-byte limit`, "ERR_SSH_RESOURCE_LIMIT", "exec");
  }
}

async function readExecInput(input: unknown, signal: AbortSignal): Promise<Uint8Array> {
  if (input === undefined) {
    return EMPTY_BYTES;
  }
  if (typeof input === "string") {
    const bytes = textEncoder.encode(input);
    checkExecInputSize(bytes.byteLength);
    return bytes;
  }
  if (input instanceof Uint8Array) {
    checkExecInputSize(input.byteLength);
    return copyRuntimeBytes(input, "SSH stdin", "exec");
  }
  if (input instanceof ArrayBuffer) {
    checkExecInputSize(input.byteLength);
    return new Uint8Array(input.slice(0));
  }
  if (input instanceof Blob) {
    if (input.size > MAX_EXEC_INPUT_BYTES) {
      checkExecInputSize(input.size);
    }
    return readBlob(input, "SSH stdin", MAX_EXEC_INPUT_BYTES, "exec", signal);
  }

  const stream = input as ReadableStream<Uint8Array>;
  if (stream.locked) {
    throw runtimeError("SSH stdin stream is already locked", "ERR_SSH_IO", "exec");
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      if (signal.aborted) {
        throw abortError(signal, "exec");
      }
      let result;
      try {
        result = await withAbort(reader.read(), signal, () => "exec");
      } catch (cause) {
        if (cause instanceof SSHError) {
          throw cause;
        }
        throw runtimeError("failed to read SSH stdin stream", "ERR_SSH_IO", "exec", cause);
      }
      if (result.done) {
        break;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        throw runtimeError("SSH stdin stream must yield Uint8Array chunks", "ERR_SSH_IO", "exec");
      }
      const nextTotal = total + chunk.byteLength;
      if (!NumberIsSafeInteger(nextTotal)) {
        throw runtimeError(
          `SSH stdin exceeds the ${MAX_EXEC_INPUT_BYTES}-byte limit`,
          "ERR_SSH_RESOURCE_LIMIT",
          "exec",
        );
      }
      checkExecInputSize(nextTotal);
      chunks.push(copyRuntimeBytes(chunk, "SSH stdin", "exec"));
      total = nextTotal;
    }
  } catch (error) {
    if (signal.aborted) {
      reader.cancel(signal.reason).catch(() => {});
    }
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {}
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < chunks.length; i++) {
    output.set(chunks[i], offset);
    offset += chunks[i].byteLength;
  }
  return output;
}

function createOperation(signal: AbortSignal | undefined, timeoutMs: number, phase: () => string) {
  const controller = new AbortController();
  let timer = null;

  function onAbort() {
    controller.abort(abortError(signal!, phase()));
  }

  if (signal !== undefined) {
    if (signal.aborted) {
      controller.abort(abortError(signal, phase()));
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  }
  if (timeoutMs !== 0 && !controller.signal.aborted) {
    timer = setTimeout(
      () => controller.abort(runtimeError("SSH operation timed out", "ERR_SSH_TIMEOUT", phase())),
      timeoutMs,
    );
  }

  return {
    signal: controller.signal,
    cleanup() {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (signal !== undefined) {
        signal.removeEventListener("abort", onAbort);
      }
    },
  };
}

async function resolvePassword(source: unknown, signal: AbortSignal, phase: () => string): Promise<Uint8Array> {
  let value = source;
  if (typeof source === "function") {
    if (signal.aborted) {
      throw abortError(signal, phase());
    }
    try {
      value = await withAbort(source({ signal }), signal, phase);
    } catch (cause) {
      if (cause instanceof SSHError) {
        throw cause;
      }
      throw runtimeError("SSH password provider failed", "ERR_SSH_AUTH", phase(), cause);
    }
  }

  if (typeof value === "string") {
    return textEncoder.encode(value);
  }
  if (value instanceof Uint8Array) {
    return copyRuntimeBytes(value, "SSH password", phase());
  }
  throw runtimeError("SSH password provider must return a string or Uint8Array", "ERR_SSH_AUTH", phase());
}

async function resolvePrivateKey(source: unknown, signal: AbortSignal, phase: () => string): Promise<Uint8Array> {
  let value = source;
  if (typeof source === "function") {
    if (signal.aborted) {
      throw abortError(signal, phase());
    }
    try {
      value = await withAbort(source({ signal }), signal, phase);
    } catch (cause) {
      if (cause instanceof SSHError) {
        throw cause;
      }
      throw runtimeError("SSH private key provider failed", "ERR_SSH_AUTH", phase(), cause);
    }
  }

  if (value instanceof Uint8Array) {
    if (value.byteLength > MAX_PRIVATE_KEY_BYTES) {
      throw runtimeError(
        `SSH private key exceeds the ${MAX_PRIVATE_KEY_BYTES}-byte limit`,
        "ERR_SSH_RESOURCE_LIMIT",
        phase(),
      );
    }
    return copyRuntimeBytes(value, "SSH private key", phase());
  }
  if (value instanceof Blob) {
    return readBlob(value, "SSH private key", MAX_PRIVATE_KEY_BYTES, phase(), signal);
  }
  throw runtimeError("SSH private key provider must return a Uint8Array or Blob", "ERR_SSH_AUTH", phase());
}

async function resolvePassphrase(source: unknown, signal: AbortSignal, phase: () => string): Promise<Uint8Array> {
  try {
    return await resolvePassword(source, signal, phase);
  } catch (cause) {
    if (cause instanceof SSHError) {
      throw cause;
    }
    throw runtimeError("SSH passphrase provider failed", "ERR_SSH_AUTH", phase(), cause);
  }
}

function nativeBytes(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw runtimeError(`Bun.SSH returned an invalid ${name} buffer`, "ERR_SSH_PROTOCOL", "exec");
  }
  return value;
}

function nativeRemoteExecution(value: unknown): string {
  return value === "may-have-started" || value === "exit-observed" || value === "not-started" ? value : "not-started";
}

class SSHResult {
  #stdout;
  #stderr;

  constructor(stdout: Uint8Array, stderr: Uint8Array, status: object, durationMs: number, remoteExecution: string) {
    this.#stdout = stdout;
    this.#stderr = stderr;
    defineProperty(this, "stdout", { value: stdout, enumerable: true });
    defineProperty(this, "stderr", { value: stderr, enumerable: true });
    defineProperty(this, "status", { value: status, enumerable: true });
    defineProperty(this, "exitCode", {
      value: (status as { type: string; code?: number }).type === "exit" ? (status as { code: number }).code : null,
      enumerable: true,
    });
    defineProperty(this, "durationMs", { value: durationMs, enumerable: true });
    defineProperty(this, "remoteExecution", { value: remoteExecution, enumerable: true });
    ObjectFreeze(this);
  }

  text(): string {
    return textDecoder.decode(this.#stdout);
  }

  json(): unknown {
    return JSON.parse(this.text());
  }
}

ObjectFreeze(SSHResult.prototype);

function resultFromNative(value: unknown, durationMs: number): SSHResult {
  if (!isRecord(value)) {
    throw runtimeError("Bun.SSH returned an invalid exec result", "ERR_SSH_PROTOCOL", "exec");
  }
  const status = snapshotExitStatus(value.status);
  if (status === undefined) {
    throw runtimeError("Bun.SSH returned an invalid exit status", "ERR_SSH_PROTOCOL", "exec");
  }
  return new SSHResult(
    nativeBytes(value.stdout, "stdout"),
    nativeBytes(value.stderr, "stderr"),
    status,
    durationMs,
    nativeRemoteExecution(value.remoteExecution),
  );
}

function retagOperation(error: SSHError, operationId: string): SSHError {
  if (error.operationId !== "") {
    return error;
  }
  const source = error as SSHError & {
    status?: object;
    stdout?: Uint8Array;
    stderr?: Uint8Array;
    cause?: unknown;
  };
  return new SSHError(error.message, {
    code: error.code,
    phase: error.phase,
    operationId,
    remoteExecution: error.remoteExecution,
    status: source.status,
    stdout: source.stdout,
    stderr: source.stderr,
    cause: source.cause,
  });
}

function exitError(code: string, message: string, result: SSHResult, operationId: string): SSHError {
  return new SSHError(message, {
    code,
    phase: "exec",
    operationId,
    remoteExecution: result.remoteExecution,
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  });
}

class SSH {
  #options;
  #native = null;
  #state = "idle";
  #info = null;
  #closed;
  #resolveClosed;
  #connectPromise = null;
  #closePromise = null;
  #closedSettled = false;
  #operationAbort = null;
  #connectWaiters = 0;
  #phase = "handshake";
  #activeChannels = 0;
  #queue = [];

  constructor(options: unknown) {
    const source = requireRecord(options, "options");
    rejectUnknownKeys(source, "", configObjectKeys);

    const hostname = requireString(ownValue(source, "options", "hostname"), "hostname");
    const username = requireString(ownValue(source, "options", "username"), "username");
    const port = optionalPositiveSafeInteger(ownValue(source, "options", "port"), "port", DEFAULT_PORT, 1, 65_535);
    const hostKey = snapshotHostKey(ownValue(source, "options", "hostKey"));
    const auth = snapshotAuth(ownValue(source, "options", "auth"));
    const connectTimeoutMs = optionalPositiveSafeInteger(
      ownValue(source, "options", "connectTimeoutMs"),
      "connectTimeoutMs",
      DEFAULT_CONNECT_TIMEOUT_MS,
    );
    const authenticationTimeoutMs = optionalPositiveSafeInteger(
      ownValue(source, "options", "authenticationTimeoutMs"),
      "authenticationTimeoutMs",
      DEFAULT_AUTHENTICATION_TIMEOUT_MS,
    );
    const maxChannels = optionalPositiveSafeInteger(
      ownValue(source, "options", "maxChannels"),
      "maxChannels",
      DEFAULT_MAX_CHANNELS,
    );
    const maxPendingOperations = optionalPositiveSafeInteger(
      ownValue(source, "options", "maxPendingOperations"),
      "maxPendingOperations",
      DEFAULT_MAX_PENDING_OPERATIONS,
    );
    const queueTimeoutMs = optionalPositiveSafeInteger(
      ownValue(source, "options", "queueTimeoutMs"),
      "queueTimeoutMs",
      DEFAULT_QUEUE_TIMEOUT_MS,
    );

    this.#options = snapshotRecord({
      hostname,
      port,
      username,
      hostKey,
      auth,
      connectTimeoutMs,
      authenticationTimeoutMs,
      maxChannels,
      maxPendingOperations,
      queueTimeoutMs,
    });
    this.#closed = new Promise(resolve => {
      this.#resolveClosed = resolve;
    });
  }

  get state() {
    return this.#state;
  }

  get info() {
    return this.#info;
  }

  get closed() {
    return this.#closed;
  }

  connect(options?: unknown): Promise<void> {
    let signal;
    try {
      signal = snapshotConnectOptions(options);
    } catch (error) {
      return Promise.reject(error);
    }

    if (this.#state === "ready") {
      return Promise.resolve();
    }
    if (this.#state === "connecting") {
      this.#connectWaiters++;
      return this.#waitForConnection(this.#connectPromise, signal);
    }
    if (this.#state !== "idle") {
      return Promise.reject(
        new SSHError("Bun.SSH cannot reconnect after it was closed or failed", {
          code: "ERR_SSH_CLOSED",
          phase: "close",
        }),
      );
    }
    if (signal !== undefined && signal.aborted) {
      return Promise.reject(abortError(signal, "handshake"));
    }

    this.#state = "connecting";
    this.#phase = "host-key";
    const operation = new AbortController();
    this.#operationAbort = operation;

    this.#connectWaiters++;
    const promise = this.#connect(operation);
    this.#connectPromise = promise;
    return this.#waitForConnection(promise, signal);
  }

  exec(command: string, options?: unknown): Promise<SSHResult> {
    let commandBytes;
    let execOptions;
    try {
      commandBytes = snapshotCommand(command);
      execOptions = snapshotExecOptions(options);
    } catch (error) {
      return Promise.reject(error);
    }

    const startedAt = performance.now();
    let phase = "handshake";
    const operation = createOperation(execOptions.signal, execOptions.timeoutMs, () => phase);
    return this.#exec(commandBytes, execOptions, operation, startedAt, value => {
      phase = value;
    });
  }

  async #exec(
    command: Uint8Array,
    options,
    operation,
    startedAt: number,
    setPhase: (phase: string) => void,
  ): Promise<SSHResult> {
    const signal = operation.signal;
    let release = null;
    let operationId = "";
    try {
      if (signal.aborted) {
        throw abortError(signal, "exec");
      }
      if (this.#state === "idle" || this.#state === "connecting") {
        await this.connect({ signal });
      } else if (this.#state !== "ready") {
        if (this.#state === "failed" || this.#state === "closed" || this.#state === "closing") {
          throw new SSHError("Bun.SSH is not available for a new operation", {
            code: "ERR_SSH_CLOSED",
            phase: "exec",
            remoteExecution: "not-started",
          });
        }
      }

      if (signal.aborted) {
        throw abortError(signal, "exec");
      }
      if (this.#state !== "ready" || this.#native === null) {
        throw new SSHError("Bun.SSH is not ready", {
          code: "ERR_SSH_CLOSED",
          phase: "exec",
          remoteExecution: "not-started",
        });
      }

      setPhase("queue");
      release = await this.#acquireChannel(signal, this.#options.queueTimeoutMs);
      setPhase("exec");
      if (signal.aborted) {
        throw abortError(signal, "exec");
      }

      const stdin = await readExecInput(options.stdin, signal);
      if (signal.aborted) {
        throw abortError(signal, "exec");
      }

      let remainingTimeout = 0;
      if (options.timeoutMs !== 0) {
        remainingTimeout = Math.ceil(startedAt + options.timeoutMs - performance.now());
        if (remainingTimeout <= 0) {
          throw runtimeError("SSH operation timed out", "ERR_SSH_TIMEOUT", "exec");
        }
      }

      const native = this.#native;
      const nativeOperation = native.execute(command, stdin, remainingTimeout, options.maxOutputBytes);
      const nativePromise = nativeOperation.promise;
      operationId = String(nativeOperation.id);
      const resultPromise = new Promise((resolve, reject) => {
        function onAbort() {
          native.cancelOperation(nativeOperation.id);
          reject(abortError(signal, "exec"));
        }
        if (signal.aborted) {
          onAbort();
          return;
        }
        signal.addEventListener("abort", onAbort, { once: true });
        Promise.resolve(nativePromise).then(
          value => {
            signal.removeEventListener("abort", onAbort);
            if (signal.aborted) {
              reject(abortError(signal, "exec"));
            } else {
              resolve(value);
            }
          },
          error => {
            signal.removeEventListener("abort", onAbort);
            reject(error);
          },
        );
      });

      let nativeResult;
      try {
        nativeResult = await resultPromise;
      } catch (error) {
        throw retagOperation(normalizeError(error, "ERR_SSH_IO", "exec"), operationId);
      }
      const result = resultFromNative(nativeResult, performance.now() - startedAt);

      if (result.status.type === "unknown") {
        throw exitError(
          "ERR_SSH_EXIT_UNKNOWN",
          "SSH command ended without a trustworthy exit status",
          result,
          operationId,
        );
      }
      if (
        options.check &&
        (result.status.type === "signal" || (result.status.type === "exit" && result.status.code !== 0))
      ) {
        throw exitError("ERR_SSH_EXIT", "SSH command exited unsuccessfully", result, operationId);
      }
      return result;
    } catch (error) {
      const normalized = normalizeError(error, "ERR_SSH_IO", "exec");
      throw operationId === "" ? normalized : retagOperation(normalized, operationId);
    } finally {
      operation.cleanup();
      if (release !== null) {
        release();
      }
    }
  }

  #acquireChannel(signal: AbortSignal, queueTimeoutMs: number): Promise<() => void> {
    if (signal.aborted) {
      return Promise.reject(abortError(signal, "queue"));
    }
    if (this.#state !== "ready") {
      return Promise.reject(
        new SSHError("Bun.SSH is not ready", {
          code: "ERR_SSH_CLOSED",
          phase: "queue",
          remoteExecution: "not-started",
        }),
      );
    }
    if (this.#activeChannels < this.#options.maxChannels) {
      this.#activeChannels++;
      return Promise.resolve(this.#channelRelease());
    }
    if (this.#queue.length >= this.#options.maxPendingOperations) {
      return Promise.reject(
        new SSHError("Bun.SSH operation queue is full", {
          code: "ERR_SSH_QUEUE_FULL",
          phase: "queue",
          remoteExecution: "not-started",
        }),
      );
    }

    return new Promise((resolve, reject) => {
      const entry = {
        resolve: null,
        reject,
        cleanup: null,
      };
      let settled = false;
      const cleanup = () => {
        if (timer !== null) {
          clearTimeout(timer);
        }
        signal.removeEventListener("abort", onAbort);
      };
      const remove = () => {
        const index = this.#queue.indexOf(entry);
        if (index !== -1) {
          this.#queue.splice(index, 1);
        }
      };
      const fail = (error: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        remove();
        reject(error);
      };
      const onAbort = () => {
        fail(abortError(signal, "queue"));
      };
      const timer =
        queueTimeoutMs === 0
          ? null
          : setTimeout(() => {
              fail(
                new SSHError("Bun.SSH operation timed out waiting for an SSH channel", {
                  code: "ERR_SSH_QUEUE_TIMEOUT",
                  phase: "queue",
                  remoteExecution: "not-started",
                }),
              );
            }, queueTimeoutMs);

      entry.resolve = () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        this.#activeChannels++;
        resolve(this.#channelRelease());
      };
      entry.cleanup = cleanup;
      signal.addEventListener("abort", onAbort, { once: true });
      this.#queue.push(entry);
    });
  }

  #channelRelease(): () => void {
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      this.#activeChannels--;
      if (this.#state === "ready") {
        const next = this.#queue.shift();
        if (next !== undefined) {
          next.resolve();
        }
      }
    };
  }

  #rejectQueued(error: SSHError) {
    while (this.#queue.length !== 0) {
      const entry = this.#queue.shift();
      entry.cleanup();
      entry.reject(error);
    }
  }

  #waitForConnection(connection: Promise<void>, signal: AbortSignal | undefined): Promise<void> {
    const wait = signal === undefined ? connection : withAbort(connection, signal, () => this.#phase);
    return wait.then(
      value => {
        this.#connectionWaiterDone();
        return value;
      },
      error => {
        this.#connectionWaiterDone();
        throw error;
      },
    );
  }

  #connectionWaiterDone() {
    this.#connectWaiters--;
    if (this.#connectWaiters === 0 && this.#state === "connecting") {
      this.#operationAbort?.abort();
    }
  }

  async #connect(operation: AbortController): Promise<void> {
    const signal = operation.signal;
    let native = null;
    let transportAdopted = false;
    let transport = null;
    let authTimer = null;

    try {
      const hostKey = this.#options.hostKey;
      let knownHosts = EMPTY_BYTES;
      let pins = null;
      if (hostKey.type === "knownHosts") {
        knownHosts = await readBlob(hostKey.file, "SSH known_hosts file", MAX_KNOWN_HOSTS_BYTES, "host-key", signal);
      } else {
        pins = hostKey.sha256;
      }

      if (signal.aborted) {
        throw abortError(signal, "host-key");
      }

      this.#phase = "handshake";
      native = this.#native = new NativeSSHConnection(
        this.#options.hostname,
        this.#options.port,
        this.#options.username,
        hostKey.type,
        knownHosts,
        pins,
        this.#options.connectTimeoutMs,
        this.#options.maxChannels,
      );

      transport = native.connectTransport();
      const info = await withAbort(transport, signal, () => "handshake");
      if (signal.aborted || this.#state !== "connecting") {
        throw abortError(signal, "handshake");
      }
      transportAdopted = true;

      this.#phase = "auth";
      const authStartedAt = performance.now();
      authTimer = setTimeout(() => operation.abort(AUTH_TIMEOUT), this.#options.authenticationTimeoutMs);
      await this.#authenticate(native, signal, authStartedAt);
      clearTimeout(authTimer);
      authTimer = null;

      if (signal.aborted || this.#state !== "connecting") {
        throw abortError(signal, "auth");
      }

      this.#info = snapshotRecord(info);
      this.#state = "ready";
    } catch (cause) {
      let error = normalizeError(cause, "ERR_SSH_CONNECT", "handshake");
      if (native !== null) {
        if (!transportAdopted && transport !== null) {
          transport.then(
            () => native.close(0).catch(() => {}),
            () => {},
          );
        }
        try {
          await native.close(0);
        } catch {}
        this.#native = null;
      }

      if (this.#state === "connecting") {
        this.#state = "failed";
        this.#settleClosed({
          reason: "failure",
          forced: false,
          error,
        });
      }
      throw error;
    } finally {
      if (authTimer !== null) {
        clearTimeout(authTimer);
      }
      this.#operationAbort = null;
    }
  }

  async #authenticate(native, signal: AbortSignal, authStartedAt: number) {
    const auth = this.#options.auth;
    const phase = () => "auth";

    if (auth.type === "password") {
      const password = await resolvePassword(auth.password, signal, phase);
      const remaining = this.#remainingAuthTime(authStartedAt);
      await withAbort(native.authenticatePassword(password, remaining), signal, phase).catch(error => {
        throw normalizeError(error, "ERR_SSH_AUTH", "auth");
      });
      return;
    }

    const key = await resolvePrivateKey(auth.key, signal, phase);
    if (auth.passphrase === undefined) {
      const remaining = this.#remainingAuthTime(authStartedAt);
      await withAbort(native.authenticatePrivateKey(key, remaining), signal, phase).catch(error => {
        throw normalizeError(error, "ERR_SSH_AUTH", "auth");
      });
      return;
    }

    const passphrase = await resolvePassphrase(auth.passphrase, signal, phase);
    const remaining = this.#remainingAuthTime(authStartedAt);
    await withAbort(native.authenticatePrivateKeyWithPassphrase(key, passphrase, remaining), signal, phase).catch(
      error => {
        throw normalizeError(error, "ERR_SSH_AUTH", "auth");
      },
    );
  }

  #remainingAuthTime(startedAt: number): number {
    const remaining = Math.ceil(startedAt + this.#options.authenticationTimeoutMs - performance.now());
    if (remaining <= 0) {
      throw runtimeError("SSH authentication timed out", "ERR_SSH_AUTH_TIMEOUT", "auth");
    }
    return remaining;
  }

  close(options?: unknown): Promise<{ forced: boolean }> {
    let closeOptions;
    try {
      closeOptions = snapshotCloseOptions(options);
    } catch (error) {
      return Promise.reject(error);
    }

    if (this.#closePromise !== null) {
      return this.#closePromise;
    }
    if (this.#state === "closed" || this.#state === "failed") {
      return Promise.resolve(snapshotRecord({ forced: false }));
    }
    if (this.#state === "idle") {
      const result = snapshotRecord({ forced: false });
      this.#state = "closed";
      this.#settleClosed({ reason: "local", forced: false });
      this.#closePromise = Promise.resolve(result);
      return this.#closePromise;
    }

    this.#state = "closing";
    this.#rejectQueued(
      new SSHError("Bun.SSH was closed before the operation started", {
        code: "ERR_SSH_CLOSED",
        phase: "queue",
        remoteExecution: "not-started",
      }),
    );
    this.#operationAbort?.abort();
    this.#closePromise = this.#close(closeOptions);
    return this.#closePromise;
  }

  async #close(options): Promise<{ forced: boolean }> {
    if (this.#connectPromise !== null) {
      try {
        await this.#connectPromise;
      } catch {}
    }

    let result = snapshotRecord({ forced: false });
    const native = this.#native;
    if (native !== null) {
      try {
        result = snapshotRecord(
          await this.#withAbortlessNativeError(native.close(options.gracePeriodMs), "ERR_SSH_IO", "close"),
        );
      } catch (cause) {
        const error = normalizeError(cause, "ERR_SSH_IO", "close");
        this.#native = null;
        this.#state = "closed";
        this.#settleClosed({ reason: "failure", forced: true, error });
        throw error;
      }
      this.#native = null;
    }

    this.#state = "closed";
    this.#settleClosed({ reason: "local", forced: result.forced });
    return result;
  }

  async #withAbortlessNativeError(value, code: string, phase: string) {
    try {
      return await value;
    } catch (error) {
      throw normalizeError(error, code, phase);
    }
  }

  #settleClosed(value) {
    if (!this.#closedSettled) {
      this.#closedSettled = true;
      this.#resolveClosed(snapshotRecord(value));
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

ObjectFreeze(SSH.prototype);

export default {
  SSH,
  SSHError,
};
