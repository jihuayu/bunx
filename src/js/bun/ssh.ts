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
const SHA256_PREFIX = "SHA256:";
const MAX_KNOWN_HOSTS_BYTES = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const EMPTY_BYTES = new Uint8Array();
const NativeSSHConnection = $bindgen("ssh_jsc.bind.ts", "SSHConnection");
const textEncoder = new TextEncoder();
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

class SSHError extends Error {
  constructor(message: string, options: { code: string; phase: string; cause?: unknown }) {
    super(message);
    this.name = "SSHError";
    defineProperty(this, "code", { value: options.code, enumerable: true });
    defineProperty(this, "phase", { value: options.phase, enumerable: true });
    defineProperty(this, "operationId", { value: "", enumerable: true });
    defineProperty(this, "remoteExecution", { value: "not-started", enumerable: true });
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
      return new SSHError(message, { code, phase, cause: error });
    }
  }

  return runtimeError("Bun.SSH operation failed", fallbackCode, fallbackPhase, error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return $isObject(value) && !ArrayIsArray(value);
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
