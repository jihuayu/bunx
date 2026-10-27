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
const SHA256_PREFIX = "SHA256:";

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

class SSH {
  #options;

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
  }

  get state() {
    return "idle";
  }

  get info() {
    return null;
  }
}

ObjectFreeze(SSH.prototype);

export default {
  SSH,
  SSHError,
};
