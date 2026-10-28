import { SSH, SSHError } from "bun";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { bunEnv, tempDir } from "harness";

const knownHosts = new Blob(["example.com ssh-ed25519 AAAA\n"]);

function validOptions() {
  return {
    hostname: "example.com",
    username: "deploy",
    hostKey: { type: "knownHosts" as const, file: knownHosts },
    auth: { type: "password" as const, password: "correct horse battery staple" },
  };
}

async function readAll(stream: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
  if (stream === null) {
    return new Uint8Array();
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
      length += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function patternedBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = i & 0xff;
  }
  return bytes;
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.byteLength).toBe(expected.byteLength);
  expect(new Bun.CryptoHasher("sha256").update(actual).digest("hex")).toBe(
    new Bun.CryptoHasher("sha256").update(expected).digest("hex"),
  );
}

function expectConfigError(fn: () => unknown): SSHError {
  let thrown: unknown;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(Error);
  expect(thrown).toBeInstanceOf(SSHError);
  expect((thrown as SSHError).code).toBe("ERR_SSH_CONFIG");
  expect((thrown as SSHError).phase).toBe("config");
  expect((thrown as SSHError).remoteExecution).toBe("not-started");
  return thrown as SSHError;
}

describe("Bun.SSH exports", () => {
  test("the named and namespace entries are the same constructors", () => {
    expect(Bun.SSH).toBe(SSH);
    expect(Bun.SSHError).toBe(SSHError);
    expect(typeof SSH).toBe("function");
    expect(typeof SSHError).toBe("function");
  });

  test("the public prototypes cannot be replaced", () => {
    expect(Object.isFrozen(SSH.prototype)).toBe(true);
    expect(Object.isFrozen(SSHError.prototype)).toBe(true);
  });
});

describe("Bun.SSH constructor", () => {
  test("creates an idle client without performing I/O", () => {
    const ssh = new SSH(validOptions());
    expect(ssh.state).toBe("idle");
    expect(ssh.info).toBeNull();
  });

  test("accepts both boundaries of the port range", () => {
    expect(new SSH({ ...validOptions(), port: 1 }).state).toBe("idle");
    expect(new SSH({ ...validOptions(), port: 65_535 }).state).toBe("idle");
  });

  test.each([0, 65_536, 22.5, NaN, Infinity, -1, "22", null])("rejects invalid port %p", port => {
    expectConfigError(() => new SSH({ ...validOptions(), port }));
  });

  test.each(["", "example\0.com"])("rejects invalid hostname %p", hostname => {
    expectConfigError(() => new SSH({ ...validOptions(), hostname }));
  });

  test.each(["", "deploy\0name"])("rejects invalid username %p", username => {
    expectConfigError(() => new SSH({ ...validOptions(), username }));
  });

  test.each([
    ["hostname", 42],
    ["username", null],
  ])("rejects non-string %s", (key, value) => {
    expectConfigError(() => new SSH({ ...validOptions(), [key]: value }));
  });

  test.each(["connectTimeoutMs", "authenticationTimeoutMs", "maxChannels", "maxPendingOperations", "queueTimeoutMs"])(
    "rejects invalid %s values",
    key => {
      for (const value of [0, -1, 1.5, NaN, Infinity, "100", null]) {
        expectConfigError(() => new SSH({ ...validOptions(), [key]: value }));
      }
    },
  );

  test("accepts positive safe integers for every limit", () => {
    const ssh = new SSH({
      ...validOptions(),
      connectTimeoutMs: 1,
      authenticationTimeoutMs: Number.MAX_SAFE_INTEGER,
      maxChannels: 1,
      maxPendingOperations: 1,
      queueTimeoutMs: Number.MAX_SAFE_INTEGER,
    });
    expect(ssh.state).toBe("idle");
  });

  test.each([[undefined], [null], [[]], ["options"], [1]])("rejects a non-object options value %p", options => {
    expectConfigError(() => new SSH(options));
  });

  test("rejects missing and unknown options", () => {
    const options = validOptions() as Record<string, unknown>;
    delete options.hostname;
    expectConfigError(() => new SSH(options));

    expectConfigError(() => new SSH({ ...validOptions(), hostnam: "example.com" }));
  });

  test("does not consult inherited properties or getters", () => {
    let getterCalls = 0;
    const prototype = {
      get hostname() {
        getterCalls++;
        return "example.com";
      },
      get username() {
        getterCalls++;
        return "deploy";
      },
      get hostKey() {
        getterCalls++;
        return knownHosts;
      },
      get auth() {
        getterCalls++;
        return { type: "password", password: "secret" };
      },
    };
    const inherited = Object.create(prototype);

    expectConfigError(() => new SSH(inherited));
    expect(getterCalls).toBe(0);
  });

  test("does not consult inherited auth or host key properties", () => {
    let getterCalls = 0;
    const hostKey = Object.create({
      get type() {
        getterCalls++;
        return "knownHosts";
      },
      get file() {
        getterCalls++;
        return knownHosts;
      },
    });
    const auth = Object.create({
      get type() {
        getterCalls++;
        return "password";
      },
      get password() {
        getterCalls++;
        return "secret";
      },
    });

    expectConfigError(() => new SSH({ ...validOptions(), hostKey, auth }));
    expect(getterCalls).toBe(0);
  });

  test("accepts an object with a null prototype", () => {
    const options = Object.assign(Object.create(null), validOptions());
    expect(new SSH(options).state).toBe("idle");
  });

  test("does not let later prototype pollution change the snapshot", () => {
    const ssh = new SSH(validOptions());
    Object.defineProperty(Object.prototype, "state", {
      configurable: true,
      get() {
        return "ready";
      },
    });
    try {
      expect(ssh.state).toBe("idle");
    } finally {
      delete Object.prototype.state;
    }
  });

  test("requires a supported host key policy", () => {
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: undefined }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "none" } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "knownHosts" } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "knownHosts", file: "known_hosts" } }));
    expectConfigError(
      () => new SSH({ ...validOptions(), hostKey: { type: "knownHosts", file: knownHosts, extra: true } }),
    );
  });

  test("accepts pinned host keys and snapshots the pin list", () => {
    const sha256: string[] = ["SHA256:first"];
    const ssh = new SSH({
      ...validOptions(),
      hostKey: { type: "pinned", sha256: sha256 as [string, ...string[]] },
    });
    sha256[0] = "changed";
    expect(ssh.state).toBe("idle");
  });

  test("rejects invalid pinned host keys", () => {
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: [] } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: ["ok", 1] } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: ["ok"] } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: ["SHA256:"] } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: ["MD5:abc"] } }));
    expectConfigError(() => new SSH({ ...validOptions(), hostKey: { type: "pinned", sha256: ["ok"], extra: true } }));
  });

  test("rejects fields from the other host key and authentication variants", () => {
    expectConfigError(
      () =>
        new SSH({
          ...validOptions(),
          hostKey: { type: "knownHosts", file: knownHosts, sha256: ["SHA256:unused"] },
        }),
    );
    expectConfigError(
      () =>
        new SSH({
          ...validOptions(),
          hostKey: { type: "pinned", sha256: ["SHA256:first"], file: knownHosts },
        }),
    );
    expectConfigError(
      () =>
        new SSH({
          ...validOptions(),
          auth: { type: "password", password: "secret", passphrase: "unused" },
        }),
    );
    expectConfigError(
      () =>
        new SSH({
          ...validOptions(),
          auth: { type: "privateKey", key: new Uint8Array([1]), password: "unused" },
        }),
    );
  });

  test("requires an explicit authentication method", () => {
    expectConfigError(() => new SSH({ ...validOptions(), auth: undefined }));
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "agent" } }));
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "none" } }));
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "password" } }));
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "password", password: 42 } }));
    expectConfigError(
      () => new SSH({ ...validOptions(), auth: { type: "password", password: "secret", extra: true } }),
    );
  });

  test("accepts password strings, byte arrays, and providers", () => {
    const bytes = new TextEncoder().encode("password");
    expect(new SSH({ ...validOptions(), auth: { type: "password", password: bytes } }).state).toBe("idle");
    expect(
      new SSH({ ...validOptions(), auth: { type: "password", password: () => new Promise(() => {}) } }).state,
    ).toBe("idle");
  });

  test("accepts private keys as bytes, Blobs, and providers", () => {
    const key = new TextEncoder().encode("private key");
    const blob = new Blob(["private key"]);
    expect(new SSH({ ...validOptions(), auth: { type: "privateKey", key } }).state).toBe("idle");
    expect(new SSH({ ...validOptions(), auth: { type: "privateKey", key: blob } }).state).toBe("idle");
    expect(new SSH({ ...validOptions(), auth: { type: "privateKey", key: () => blob } }).state).toBe("idle");
  });

  test("rejects invalid private keys, passphrases, and unknown fields", () => {
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "privateKey" } }));
    expectConfigError(() => new SSH({ ...validOptions(), auth: { type: "privateKey", key: "private key" } }));
    expectConfigError(
      () => new SSH({ ...validOptions(), auth: { type: "privateKey", key: new Uint8Array(), passphrase: 42 } }),
    );
    expectConfigError(
      () => new SSH({ ...validOptions(), auth: { type: "privateKey", key: new Uint8Array(), extra: true } }),
    );
  });

  test("does not invoke password or passphrase providers during construction", () => {
    let calls = 0;
    const provider = () => {
      calls++;
      return "secret";
    };

    new SSH({ ...validOptions(), auth: { type: "password", password: provider } });
    new SSH({
      ...validOptions(),
      auth: { type: "privateKey", key: new Uint8Array([1]), passphrase: provider },
    });

    expect(calls).toBe(0);
  });

  test("does not read Blob host keys or private keys during construction", () => {
    function trackedBlob() {
      const blob = new Blob(["secret"]);
      for (const method of ["text", "arrayBuffer", "bytes", "stream"]) {
        Object.defineProperty(blob, method, {
          value() {
            throw new Error(`constructor read Blob.${method}()`);
          },
        });
      }
      return blob;
    }

    const ssh = new SSH({
      ...validOptions(),
      hostKey: { type: "knownHosts", file: trackedBlob() },
      auth: { type: "privateKey", key: trackedBlob() },
    });
    expect(ssh.state).toBe("idle");
  });

  test("validates connect and close options before doing I/O", async () => {
    const ssh = new SSH(validOptions());
    await expect(ssh.connect({ timeoutMs: 1 })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.connect({ signal: true })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });

    const controller = new AbortController();
    controller.abort();
    await expect(ssh.connect({ signal: controller.signal })).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
    });
    expect(ssh.state).toBe("idle");

    await expect(ssh.close({ force: 1 })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    expect(ssh.state).toBe("idle");
  });

  test("validates exec arguments without doing I/O", async () => {
    const ssh = new SSH(validOptions());
    await expect(ssh.exec("")).rejects.toMatchObject({ code: "ERR_SSH_CONFIG", phase: "config" });
    await expect(ssh.exec("echo\0hidden")).rejects.toMatchObject({ code: "ERR_SSH_CONFIG", phase: "config" });
    await expect(ssh.exec("true", { unknown: true })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.exec("true", { timeoutMs: -1 })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.exec("true", { stdin: 42 })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });

    const controller = new AbortController();
    controller.abort();
    await expect(ssh.exec("true", { signal: controller.signal })).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
    });
    expect(ssh.state).toBe("idle");
  });

  test("validates spawn arguments without doing I/O", async () => {
    const ssh = new SSH(validOptions());
    await expect(ssh.spawn("")).rejects.toMatchObject({ code: "ERR_SSH_CONFIG", phase: "config" });
    await expect(ssh.spawn("true", { stdin: { data: 42 } })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.spawn("true", { stdin: { unknown: true } })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.spawn("true", { stdout: "text" })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });
    await expect(ssh.spawn("true", { stderr: "text" })).rejects.toMatchObject({
      code: "ERR_SSH_CONFIG",
      phase: "config",
    });

    const controller = new AbortController();
    controller.abort();
    await expect(ssh.spawn("true", { signal: controller.signal })).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
    });
    expect(ssh.state).toBe("idle");
  });
});

const sshd =
  process.platform === "win32" ? null : ["/usr/sbin/sshd", "/usr/local/sbin/sshd"].find(path => existsSync(path));
const sshKeygen =
  process.platform === "win32"
    ? null
    : ["/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"].find(path => existsSync(path));

function run(cmd: string[]) {
  const result = Bun.spawnSync({
    cmd,
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `${cmd[0]} exited with ${result.exitCode}\n${result.stdout.toString()}\n${result.stderr.toString()}`,
    );
  }
}

function reservePort(): number {
  const listener = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      data() {},
    },
  });
  const port = listener.port;
  listener.stop(true);
  return port;
}

async function waitForPort(port: number, process: Bun.Subprocess) {
  const deadline = performance.now() + 5_000;
  while (performance.now() < deadline) {
    if (process.exitCode !== null) {
      const stderr = await process.stderr.text();
      throw new Error(`sshd exited before listening on ${port}\n${stderr}`);
    }
    try {
      const socket = await Bun.connect({
        hostname: "127.0.0.1",
        port,
        socket: {
          data() {},
        },
      });
      socket.end();
      return;
    } catch {
      await new Promise(resolve => setImmediate(resolve));
    }
  }
  throw new Error(`sshd did not listen on ${port}`);
}

describe.skipIf(!sshd || !sshKeygen)("Bun.SSH connection", () => {
  let dir: string & Disposable;
  let server: Bun.Subprocess;
  let port: number;
  let username: string;
  let knownHosts: Blob;
  let privateKey: Blob;
  let encryptedPrivateKey: Blob;
  let hostKeyFingerprint: string;
  let wrongPinsHostKey: Bun.SSHHostKeyPolicy;

  function client(overrides: Record<string, unknown> = {}) {
    return new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "privateKey", key: privateKey },
      ...overrides,
    });
  }

  async function connectedClient(overrides: Record<string, unknown> = {}) {
    const ssh = client(overrides);
    await ssh.connect();
    return ssh;
  }

  async function terminateWorkerWhenReady(source: string) {
    const workerUrl = URL.createObjectURL(
      new Blob([source], {
        type: "application/javascript",
      }),
    );
    const worker = new Worker(workerUrl);
    try {
      await new Promise<void>((resolve, reject) => {
        worker.addEventListener("message", event => {
          if (event.data === "ready") {
            resolve();
          }
        });
        worker.addEventListener("error", event => {
          reject(event.error ?? new Error(event.message));
        });
      });

      const started = performance.now();
      await worker.terminate();
      expect(performance.now() - started).toBeLessThan(1_000);
    } finally {
      await worker.terminate();
      URL.revokeObjectURL(workerUrl);
    }
  }

  beforeAll(async () => {
    dir = tempDir("bun-ssh-connection", {});
    port = reservePort();
    username = process.env.USER || process.env.LOGNAME || "";
    if (username === "") {
      throw new Error("sshd integration test needs USER or LOGNAME");
    }

    const hostKey = join(dir, "host_key");
    const clientKey = join(dir, "client_key");
    const encryptedClientKey = join(dir, "encrypted_client_key");
    run([sshKeygen!, "-q", "-t", "ed25519", "-N", "", "-f", hostKey]);
    run([sshKeygen!, "-q", "-t", "ed25519", "-N", "", "-f", clientKey]);
    run([sshKeygen!, "-q", "-t", "ed25519", "-N", "test-passphrase", "-f", encryptedClientKey]);

    const authorizedKeys = join(dir, "authorized_keys");
    await Bun.write(
      authorizedKeys,
      `${await Bun.file(`${clientKey}.pub`).text()}${await Bun.file(`${encryptedClientKey}.pub`).text()}`,
    );
    const publicKey = (await Bun.file(`${hostKey}.pub`).text()).trim().split(/\s+/).slice(0, 2).join(" ");
    await Bun.write(join(dir, "known_hosts"), `[127.0.0.1]:${port} ${publicKey}\n`);
    const fingerprintLine = Bun.spawnSync({
      cmd: [sshKeygen!, "-l", "-f", `${hostKey}.pub`],
      env: bunEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    if (fingerprintLine.exitCode !== 0) {
      throw new Error(`ssh-keygen -l failed\n${fingerprintLine.stderr.toString()}`);
    }
    hostKeyFingerprint = fingerprintLine.stdout.toString().trim().split(/\s+/)[1];
    if (!hostKeyFingerprint.startsWith("SHA256:")) {
      throw new Error(`unexpected host key fingerprint: ${hostKeyFingerprint}`);
    }

    const config = join(dir, "sshd_config");
    await Bun.write(
      config,
      [
        `Port ${port}`,
        "ListenAddress 127.0.0.1",
        `HostKey ${hostKey}`,
        `PidFile ${join(dir, "sshd.pid")}`,
        `AuthorizedKeysFile ${authorizedKeys}`,
        "StrictModes no",
        "UsePAM no",
        "PasswordAuthentication yes",
        "KbdInteractiveAuthentication no",
        "ChallengeResponseAuthentication no",
        "PermitRootLogin no",
        `AllowUsers ${username}`,
        "LogLevel ERROR",
        "",
      ].join("\n"),
    );

    server = Bun.spawn({
      cmd: [sshd!, "-D", "-e", "-f", config],
      env: bunEnv,
      stdout: "ignore",
      stderr: "pipe",
    });
    await waitForPort(port, server);

    knownHosts = Bun.file(join(dir, "known_hosts"));
    privateKey = Bun.file(clientKey);
    encryptedPrivateKey = Bun.file(encryptedClientKey);
    wrongPinsHostKey = { type: "pinned", sha256: ["SHA256:not-the-server-key"] };
  });

  afterAll(async () => {
    if (server && server.exitCode === null) {
      server.kill();
      await server.exited;
    }
    dir?.[Symbol.dispose]();
  });

  test("connects, authenticates with a private key, and closes idempotently", async () => {
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "privateKey", key: privateKey },
      connectTimeoutMs: 5_000,
      authenticationTimeoutMs: 5_000,
    });

    expect(ssh.state).toBe("idle");
    expect(ssh.info).toBeNull();
    await ssh.connect();
    expect(ssh.state).toBe("ready");
    expect(ssh.info).toMatchObject({
      hostname: "127.0.0.1",
      port,
      username,
      hostKeyAlgorithm: "ssh-ed25519",
    });
    expect(ssh.info!.hostKeySHA256).toStartWith("SHA256:");
    expect(ssh.info!.cipherClientToServer).toBe(ssh.info!.cipherServerToClient);
    expect(ssh.info!.cipherClientToServer).not.toBe("unknown");

    const firstClose = ssh.close();
    const secondClose = ssh.close();
    expect(await firstClose).toEqual({ forced: false });
    expect(await secondClose).toEqual({ forced: false });
    expect(ssh.state).toBe("closed");
    expect(await ssh.closed).toEqual({ reason: "local", forced: false });
    await expect(ssh.connect()).rejects.toMatchObject({
      code: "ERR_SSH_CLOSED",
      phase: "close",
    });
  });

  test("large safe-integer timeouts do not overflow into immediate deadlines", async () => {
    const ssh = client({
      connectTimeoutMs: Number.MAX_SAFE_INTEGER,
      authenticationTimeoutMs: Number.MAX_SAFE_INTEGER,
      queueTimeoutMs: Number.MAX_SAFE_INTEGER,
    });
    await ssh.connect();
    const result = await ssh.exec("printf large-timeout", {
      timeoutMs: Number.MAX_SAFE_INTEGER,
      maxOutputBytes: 64,
    });
    expect(result.text()).toBe("large-timeout");
    expect(await ssh.close()).toEqual({ forced: false });
  });

  test("resolves an encrypted private key passphrase only after host verification", async () => {
    let passphraseCalls = 0;
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: {
        type: "privateKey",
        key: encryptedPrivateKey,
        passphrase: ({ signal }) => {
          expect(signal.aborted).toBe(false);
          passphraseCalls++;
          return "test-passphrase";
        },
      },
    });

    await ssh.connect();
    expect(passphraseCalls).toBe(1);
    await ssh.close();
  });

  test("accepts a matching pin after earlier non-matching pins", async () => {
    let keyCalls = 0;
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: {
        type: "pinned",
        sha256: ["SHA256:not-the-server-key", hostKeyFingerprint],
      },
      auth: {
        type: "privateKey",
        key: () => {
          keyCalls++;
          return privateKey;
        },
      },
      authenticationTimeoutMs: 5_000,
    });

    await ssh.connect();
    expect(ssh.state).toBe("ready");
    expect(ssh.info!.hostKeySHA256).toBe(hostKeyFingerprint);
    expect(keyCalls).toBe(1);
    await ssh.close();
  });

  test("one cancelled connect waiter does not cancel another waiter", async () => {
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "privateKey", key: privateKey },
    });
    const controller = new AbortController();
    const cancelled = ssh.connect({ signal: controller.signal });
    const remaining = ssh.connect();

    controller.abort();
    await expect(cancelled).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
    });
    await remaining;
    expect(ssh.state).toBe("ready");
    await ssh.close();
  });

  test("cancelling the last connect waiter leaves the client reusable", async () => {
    const ssh = client();
    const controller = new AbortController();
    const connecting = ssh.connect({ signal: controller.signal });

    controller.abort();
    await expect(connecting).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
    });
    expect(ssh.state).toBe("idle");
    expect(ssh.info).toBeNull();

    await ssh.connect();
    expect(ssh.state).toBe("ready");
    await ssh.close();
  });

  test("a failed host key check never invokes a secret provider", async () => {
    let passwordCalls = 0;
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: wrongPinsHostKey,
      auth: {
        type: "password",
        password: () => {
          passwordCalls++;
          return "must-not-be-used";
        },
      },
    });

    const error = await ssh.connect().catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_HOST_KEY_UNKNOWN",
      phase: "host-key",
    });
    expect(passwordCalls).toBe(0);
    expect(ssh.state).toBe("failed");
    expect(await ssh.closed).toMatchObject({
      reason: "failure",
      forced: false,
      error,
    });
  });

  test("surfaces rejected password authentication as an SSHError", async () => {
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "password", password: "definitely the wrong password" },
      authenticationTimeoutMs: 5_000,
    });

    const error = await ssh.connect().catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_AUTH",
      phase: "auth",
    });
    expect(ssh.state).toBe("failed");
    expect((await ssh.closed).reason).toBe("failure");
  });

  test("bounds a secret provider that ignores its abort signal", async () => {
    let providerSignal: AbortSignal | undefined;
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: {
        type: "password",
        password: ({ signal }) => {
          providerSignal = signal;
          return new Promise(() => {});
        },
      },
      authenticationTimeoutMs: 100,
    });

    const error = await ssh.connect().catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_AUTH_TIMEOUT",
      phase: "auth",
    });
    expect(providerSignal?.aborted).toBe(true);
    expect(ssh.state).toBe("failed");
    expect((await ssh.closed).reason).toBe("failure");
  });

  test("connect timeout bounds known_hosts Blob reads", async () => {
    const hangingKnownHosts = new Blob(["placeholder"]);
    Object.defineProperty(hangingKnownHosts, "bytes", {
      value: () => new Promise(() => {}),
    });
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: hangingKnownHosts },
      auth: { type: "password", password: "unused" },
      connectTimeoutMs: 100,
    });

    const error = await ssh.connect().catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_CONNECT_TIMEOUT",
      phase: "host-key",
    });
    expect(ssh.state).toBe("failed");
    expect((await ssh.closed).reason).toBe("failure");
  });

  test("idle close performs no I/O and async disposal uses close", async () => {
    const idle = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "privateKey", key: privateKey },
    });
    expect(await idle.close()).toEqual({ forced: false });
    expect(idle.state).toBe("closed");
    expect(await idle.closed).toEqual({ reason: "local", forced: false });

    const ready = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "knownHosts", file: knownHosts },
      auth: { type: "privateKey", key: privateKey },
    });
    await ready.connect();
    await ready[Symbol.asyncDispose]();
    expect(ready.state).toBe("closed");
  });

  test("close during a stalled handshake settles the client without waiting for the connect deadline", async () => {
    const listener = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data() {},
      },
    });
    try {
      const ssh = new SSH({
        hostname: "127.0.0.1",
        port: listener.port,
        username,
        hostKey: { type: "pinned", sha256: ["SHA256:unused"] },
        auth: { type: "password", password: "unused" },
        connectTimeoutMs: 2_000,
      });
      const connecting = ssh.connect().catch(error => error);
      expect(ssh.state).toBe("connecting");

      const started = performance.now();
      const closeResult = await ssh.close();
      const connectError = await connecting;
      expect(performance.now() - started).toBeLessThan(1_000);
      expect(closeResult).toEqual({ forced: false });
      expect(connectError).toBeInstanceOf(SSHError);
      expect(connectError).toMatchObject({ code: "ERR_SSH_ABORTED" });
      expect(ssh.state).toBe("closed");
      expect(await ssh.closed).toEqual({ reason: "local", forced: false });
    } finally {
      listener.stop(true);
    }
  });

  test("worker termination cancels an in-flight SSH connection", async () => {
    let accepted = () => {};
    const connected = new Promise<void>(resolve => {
      accepted = resolve;
    });
    const listener = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open() {
          accepted();
        },
        data() {},
      },
    });
    let worker: Worker | undefined;
    let workerUrl: string | undefined;
    try {
      workerUrl = URL.createObjectURL(
        new Blob(
          [
            `
              const ssh = new Bun.SSH({
                hostname: "127.0.0.1",
                port: ${listener.port},
                username: "worker",
                hostKey: { type: "pinned", sha256: ["SHA256:unused"] },
                auth: { type: "password", password: "unused" },
                connectTimeoutMs: 60_000,
              });
              ssh.connect().catch(() => {});
            `,
          ],
          { type: "application/javascript" },
        ),
      );
      worker = new Worker(
        workerUrl,
      );
      await connected;

      const started = performance.now();
      await worker.terminate();
      expect(performance.now() - started).toBeLessThan(1_000);
    } finally {
      await worker?.terminate();
      if (workerUrl !== undefined) {
        URL.revokeObjectURL(workerUrl);
      }
      listener.stop(true);
    }
  });

  test("worker termination cancels in-flight exec and spawn jobs", async () => {
    const knownHostsText = await knownHosts.text();
    const privateKeyText = await privateKey.text();
    const clientSource = `
      const ssh = new Bun.SSH({
        hostname: "127.0.0.1",
        port: ${port},
        username: ${JSON.stringify(username)},
        hostKey: { type: "knownHosts", file: new Blob([${JSON.stringify(knownHostsText)}]) },
        auth: {
          type: "privateKey",
          key: new TextEncoder().encode(${JSON.stringify(privateKeyText)}),
        },
        connectTimeoutMs: 5_000,
        authenticationTimeoutMs: 5_000,
      });
      await ssh.connect();
    `;

    await terminateWorkerWhenReady(
      `${clientSource}
       ssh.exec("sleep 60", { timeoutMs: 0 }).catch(() => {});
       postMessage("ready");`,
    );
    await terminateWorkerWhenReady(
      `${clientSource}
       await ssh.spawn("sleep 60", { stdout: "ignore", stderr: "ignore" });
       postMessage("ready");`,
    );
  });

  test("connect timeout reports the native handshake phase", async () => {
    const listener = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data() {},
      },
    });
    try {
      const ssh = new SSH({
        hostname: "127.0.0.1",
        port: listener.port,
        username,
        hostKey: { type: "pinned", sha256: ["SHA256:unused"] },
        auth: { type: "password", password: "unused" },
        connectTimeoutMs: 150,
      });

      const error = await ssh.connect().catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_CONNECT_TIMEOUT",
        phase: "handshake",
      });
      expect(ssh.state).toBe("failed");
      expect(await ssh.closed).toMatchObject({ reason: "failure", error });
    } finally {
      listener.stop(true);
    }
  });

  test("force close aborts an operation blocked reading stdin", async () => {
    const ssh = await connectedClient();
    let notifyPull = () => {};
    const pullStarted = new Promise<void>(resolve => {
      notifyPull = resolve;
    });
    const input = new ReadableStream<Uint8Array>(
      {
        pull() {
          notifyPull();
          return new Promise(() => {});
        },
      },
      { highWaterMark: 0 },
    );

    const executing = ssh.exec("cat", { stdin: input, timeoutMs: 0 }).catch(error => error);
    await pullStarted;
    const closing = ssh.close({ force: true });
    const [error, result] = await Promise.all([executing, closing]);

    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_ABORTED",
      phase: "exec",
    });
    expect(result).toEqual({ forced: true });
    expect(ssh.state).toBe("closed");
  });

  test("reports a refused TCP connection in the tcp phase", async () => {
    const port = reservePort();
    const ssh = new SSH({
      hostname: "127.0.0.1",
      port,
      username,
      hostKey: { type: "pinned", sha256: ["SHA256:unused"] },
      auth: { type: "password", password: "unused" },
      connectTimeoutMs: 1_000,
    });

    const error = await ssh.connect().catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error).toMatchObject({
      code: "ERR_SSH_CONNECT",
      phase: "tcp",
    });
    expect(ssh.state).toBe("failed");
    expect(await ssh.closed).toMatchObject({ reason: "failure", error });
  });

  test("exec captures stdout and stderr and reports an explicit non-zero exit", async () => {
    const ssh = await connectedClient();
    try {
      const result = await ssh.exec("printf 'stdout'; printf 'stderr' >&2; exit 7");
      expect(result.stdout).toEqual(new TextEncoder().encode("stdout"));
      expect(result.stderr).toEqual(new TextEncoder().encode("stderr"));
      expect(result.status).toEqual({ type: "exit", code: 7 });
      expect(result.exitCode).toBe(7);
      expect(result.remoteExecution).toBe("exit-observed");
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.text()).toBe("stdout");
      expect(result.text()).toBe("stdout");

      const error = await ssh
        .exec("printf 'partial'; printf 'warning' >&2; exit 9", { check: true })
        .catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_EXIT",
        phase: "exec",
        status: { type: "exit", code: 9 },
        remoteExecution: "exit-observed",
      });
      expect(new TextDecoder().decode(error.stdout)).toBe("partial");
      expect(new TextDecoder().decode(error.stderr)).toBe("warning");
    } finally {
      await ssh.close();
    }
  });

  test("exec preserves exit code 255", async () => {
    const ssh = await connectedClient();
    try {
      const result = await ssh.exec("exit 255");
      expect(result.status).toEqual({ type: "exit", code: 255 });
      expect(result.exitCode).toBe(255);
      expect(result.remoteExecution).toBe("exit-observed");
    } finally {
      await ssh.close();
    }
  });

  test("exec sends binary stdin and resolves JSON without replaying the command", async () => {
    const ssh = await connectedClient();
    try {
      const input = new Uint8Array([0, 1, 2, 127, 128, 255]);
      const result = await ssh.exec("cat", { stdin: input });
      expect(result.stdout).toEqual(input);

      const json = await ssh.exec("printf '{\"ok\":true}'");
      expect(json.json()).toEqual({ ok: true });
      expect(json.json()).toEqual({ ok: true });
    } finally {
      await ssh.close();
    }
  });

  test("exec admits output exactly at the byte budget and rejects the next byte", async () => {
    const ssh = await connectedClient();
    try {
      const exact = await ssh.exec("printf '12345'", { maxOutputBytes: 5 });
      expect(exact.text()).toBe("12345");

      const error = await ssh.exec("printf '123456'", { maxOutputBytes: 5 }).catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_OUTPUT_LIMIT",
        phase: "exec",
      });
      expect(error.stdout.byteLength + error.stderr.byteLength).toBeLessThanOrEqual(5);
    } finally {
      await ssh.close();
    }
  });

  test("exec applies one byte budget across stdout and stderr", async () => {
    const ssh = await connectedClient();
    try {
      const exact = await ssh.exec("printf '123'; printf '45' >&2", {
        maxOutputBytes: 5,
      });
      expect(exact.stdout).toEqual(new TextEncoder().encode("123"));
      expect(exact.stderr).toEqual(new TextEncoder().encode("45"));

      const error = await ssh
        .exec("printf '123'; printf '456' >&2", {
          maxOutputBytes: 5,
        })
        .catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_OUTPUT_LIMIT",
        phase: "exec",
      });
      expect(error.stdout.byteLength + error.stderr.byteLength).toBeLessThanOrEqual(5);
    } finally {
      await ssh.close();
    }
  });

  test(
    "exec shares the connection output budget",
    async () => {
      const ssh = await connectedClient();
      try {
        const bytes = 32 * 1024 * 1024 + 1;
        const error = await ssh
          .exec(`head -c ${bytes} /dev/zero`, {
            maxOutputBytes: bytes,
            timeoutMs: 15_000,
          })
          .catch(error => error);
        expect(error).toBeInstanceOf(SSHError);
        expect(error).toMatchObject({
          code: "ERR_SSH_RESOURCE_LIMIT",
          phase: "exec",
        });
        expect(error.stdout.byteLength).toBeLessThanOrEqual(32 * 1024 * 1024);
      } finally {
        await ssh.close();
      }
    },
    15_000,
  );

  test("exec drains large stdout and stderr concurrently", async () => {
    const ssh = await connectedClient();
    try {
      const bytesPerStream = 2 * 1024 * 1024 + 4096;
      const result = await ssh.exec(
        `head -c ${bytesPerStream} /dev/zero & head -c ${bytesPerStream} /dev/zero >&2 & wait`,
        { maxOutputBytes: bytesPerStream * 2 },
      );
      expect(result.stdout.byteLength).toBe(bytesPerStream);
      expect(result.stderr.byteLength).toBe(bytesPerStream);
      expect(result.stdout.every(byte => byte === 0)).toBe(true);
      expect(result.stderr.every(byte => byte === 0)).toBe(true);
      expect(result.status).toEqual({ type: "exit", code: 0 });
    } finally {
      await ssh.close();
    }
  });

  test("exec writes stdin larger than a channel window", async () => {
    const ssh = await connectedClient();
    try {
      const input = patternedBytes(2 * 1024 * 1024 + 4096);
      const result = await ssh.exec("cat", { stdin: input, maxOutputBytes: input.byteLength });
      expectBytes(result.stdout, input);
      expect(result.stderr.byteLength).toBe(0);
      expect(result.status).toEqual({ type: "exit", code: 0 });
    } finally {
      await ssh.close();
    }
  });

  test("exec rejects a locked or failing stdin stream without poisoning the connection", async () => {
    const ssh = await connectedClient();
    try {
      const locked = new ReadableStream<Uint8Array>();
      const reader = locked.getReader();
      await expect(ssh.exec("cat", { stdin: locked })).rejects.toMatchObject({
        code: "ERR_SSH_IO",
        phase: "exec",
      });
      reader.releaseLock();

      const failing = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3]));
          controller.error(new Error("stdin failed"));
        },
      });
      await expect(ssh.exec("cat", { stdin: failing })).rejects.toMatchObject({
        code: "ERR_SSH_IO",
        phase: "exec",
      });

      expect((await ssh.exec("printf still-ready")).text()).toBe("still-ready");
    } finally {
      await ssh.close();
    }
  });

  test("an already aborted exec does not read stdin or reach the remote command", async () => {
    const ssh = await connectedClient();
    try {
      const marker = join(dir, "aborted-exec-marker");
      let reads = 0;
      const input = new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            reads++;
            controller.enqueue(new Uint8Array([1]));
            controller.close();
          },
        },
        { highWaterMark: 0 },
      );
      const controller = new AbortController();
      controller.abort();
      const error = await ssh
        .exec(`touch ${JSON.stringify(marker)}`, { signal: controller.signal, stdin: input })
        .catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error.code).toBe("ERR_SSH_ABORTED");
      expect(error.phase).toBe("exec");
      expect(reads).toBe(0);
      expect(await Bun.file(marker).exists()).toBe(false);
      expect(ssh.state).toBe("ready");
    } finally {
      await ssh.close();
    }
  });

  test("exec cancellation bounds one channel without poisoning the connection", async () => {
    const ssh = await connectedClient();
    try {
      const controller = new AbortController();
      const pending = ssh.exec("sleep 5", { signal: controller.signal, timeoutMs: 0 }).catch(error => error);
      setTimeout(() => controller.abort(), 100);
      const error = await pending;
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_ABORTED",
        phase: "exec",
      });

      const result = await ssh.exec("printf 'still-ready'");
      expect(result.text()).toBe("still-ready");
    } finally {
      await ssh.close();
    }
  });

  test("exec timeout is distinguishable from caller cancellation", async () => {
    const ssh = await connectedClient();
    try {
      const error = await ssh
        .exec("printf partial; printf warning >&2; sleep 5", { timeoutMs: 500 })
        .catch(error => error);
      expect(error).toBeInstanceOf(SSHError);
      expect(error).toMatchObject({
        code: "ERR_SSH_TIMEOUT",
        phase: "exec",
      });
      expect(new TextDecoder().decode(error.stdout)).toBe("partial");
      expect(new TextDecoder().decode(error.stderr)).toBe("warning");

      const result = await ssh.exec("printf 'after-timeout'");
      expect(result.text()).toBe("after-timeout");
    } finally {
      await ssh.close();
    }
  });

  test("spawn exposes independent stdout and stderr streams with an explicit exit status", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("printf stdout; printf stderr >&2; exit 7");
      expect(proc.stdin).toBeNull();
      expect(proc.stdout).not.toBeNull();
      expect(proc.stderr).not.toBeNull();

      const [stdout, stderr, status] = await Promise.all([readAll(proc.stdout), readAll(proc.stderr), proc.exited]);
      expect(new TextDecoder().decode(stdout)).toBe("stdout");
      expect(new TextDecoder().decode(stderr)).toBe("stderr");
      expect(status).toEqual({ type: "exit", code: 7 });
      await proc.closed;
      expect(proc.exitCode).toBe(7);
      expect(proc.remoteExecution).toBe("exit-observed");
    } finally {
      await ssh.close();
    }
  });

  test("spawn supports pipe stdin, data wrappers, and ignored stdin", async () => {
    const ssh = await connectedClient();
    try {
      const piped = await ssh.spawn("cat", { stdin: "pipe" });
      const input = new Uint8Array([0, 1, 2, 127, 128, 255]);
      await expect(piped.sendSignal("SIGTERM" as Bun.SSHSignal)).rejects.toMatchObject({
        code: "ERR_SSH_CONFIG",
        phase: "config",
      });
      const writer = piped.stdin!.getWriter();
      await writer.write(input);
      await writer.close();
      expect(await readAll(piped.stdout)).toEqual(input);
      expect(await piped.exited).toEqual({ type: "exit", code: 0 });
      await piped.closed;

      const wrapped = await ssh.spawn("cat", { stdin: { data: "pipe" } });
      expect(new TextDecoder().decode(await readAll(wrapped.stdout))).toBe("pipe");
      expect(await wrapped.exited).toEqual({ type: "exit", code: 0 });
      await wrapped.closed;

      const ignored = await ssh.spawn("cat", { stdin: "ignore" });
      expect((await readAll(ignored.stdout)).byteLength).toBe(0);
      expect(await ignored.exited).toEqual({ type: "exit", code: 0 });
      await ignored.closed;
    } finally {
      await ssh.close();
    }
  });

  test("spawn drains large stdout and stderr concurrently", async () => {
    const ssh = await connectedClient();
    try {
      const bytesPerStream = 2 * 1024 * 1024 + 4096;
      const proc = await ssh.spawn(
        `head -c ${bytesPerStream} /dev/zero & head -c ${bytesPerStream} /dev/zero >&2 & wait`,
      );
      const [stdout, stderr, status] = await Promise.all([readAll(proc.stdout), readAll(proc.stderr), proc.exited]);
      expect(stdout.byteLength).toBe(bytesPerStream);
      expect(stderr.byteLength).toBe(bytesPerStream);
      expect(stdout.every(byte => byte === 0)).toBe(true);
      expect(stderr.every(byte => byte === 0)).toBe(true);
      expect(status).toEqual({ type: "exit", code: 0 });
      await proc.closed;
    } finally {
      await ssh.close();
    }
  });

  test("spawn writes stdin larger than a channel window through a pipe", async () => {
    const ssh = await connectedClient();
    try {
      const input = patternedBytes(2 * 1024 * 1024 + 4096);
      const proc = await ssh.spawn("cat", { stdin: "pipe" });
      const output = readAll(proc.stdout);
      const writer = proc.stdin!.getWriter();
      await writer.write(input);
      await writer.close();
      expectBytes(await output, input);
      expect(await proc.exited).toEqual({ type: "exit", code: 0 });
      await proc.closed;
    } finally {
      await ssh.close();
    }
  });

  test("spawn accepts Blob and byte streams as initial stdin", async () => {
    const ssh = await connectedClient();
    try {
      const input = patternedBytes(512 * 1024);
      for (const data of [
        new Blob([input]),
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(input.subarray(0, 128 * 1024));
            controller.enqueue(input.subarray(128 * 1024));
            controller.close();
          },
        }),
      ]) {
        const proc = await ssh.spawn("cat", { stdin: { data } });
        expectBytes(await readAll(proc.stdout), input);
        expect(await proc.exited).toEqual({ type: "exit", code: 0 });
        await proc.closed;
      }
    } finally {
      await ssh.close();
    }
  });

  test("spawn ignores each output branch while continuing to drain the channel", async () => {
    const ssh = await connectedClient();
    try {
      const stdoutIgnored = await ssh.spawn("head -c 400000 /dev/zero; printf stderr >&2", {
        stdout: "ignore",
      });
      expect(stdoutIgnored.stdout).toBeNull();
      expect(new TextDecoder().decode(await readAll(stdoutIgnored.stderr))).toBe("stderr");
      expect(await stdoutIgnored.exited).toEqual({ type: "exit", code: 0 });
      await stdoutIgnored.closed;

      const stderrIgnored = await ssh.spawn("printf stdout; head -c 400000 /dev/zero >&2", {
        stderr: "ignore",
      });
      expect(stderrIgnored.stderr).toBeNull();
      expect(new TextDecoder().decode(await readAll(stderrIgnored.stdout))).toBe("stdout");
      expect(await stderrIgnored.exited).toEqual({ type: "exit", code: 0 });
      await stderrIgnored.closed;
    } finally {
      await ssh.close();
    }
  });

  test(
    "a paused output stream cannot stall the other stream or exit status",
    async () => {
      const ssh = await connectedClient();
      try {
        const proc = await ssh.spawn("head -c 9437184 /dev/zero; printf tail >&2", {
          timeoutMs: 5_000,
        });

        expect(new TextDecoder().decode(await readAll(proc.stderr))).toBe("tail");
        expect(await proc.exited).toEqual({ type: "exit", code: 0 });
        await proc.closed;

        const reader = proc.stdout!.getReader();
        let retained = 0;
        let error: unknown;
        try {
          for (;;) {
            const result = await reader.read();
            if (result.done) {
              break;
            }
            retained += result.value.byteLength;
          }
        } catch (cause) {
          error = cause;
        } finally {
          reader.releaseLock();
        }

        expect(retained).toBeLessThanOrEqual(512 * 1024);
        expect(error).toBeInstanceOf(SSHError);
        expect(error).toMatchObject({
          code: "ERR_SSH_OUTPUT_LIMIT",
          phase: "io",
        });
      } finally {
        await ssh.close();
      }
    },
    5_000,
  );

  test(
    "spawn channels bound buffered output until the consumer catches up",
    async () => {
      const ssh = await connectedClient();
      try {
        const bytesPerProcess = 8 * 1024 * 1024;
        const processes = await Promise.all(
          Array.from({ length: 5 }, () =>
            ssh.spawn(`head -c ${bytesPerProcess} /dev/zero`, {
              stderr: "ignore",
              timeoutMs: 15_000,
            }),
          ),
        );

        await Promise.all(processes.map(process => process.closed));
        const results = await Promise.all(
          processes.map(async process => {
            const reader = process.stdout!.getReader();
            let retained = 0;
            let error: unknown;
            try {
              for (;;) {
                const result = await reader.read();
                if (result.done) {
                  break;
                }
                retained += result.value.byteLength;
              }
            } catch (cause) {
              error = cause;
            } finally {
              reader.releaseLock();
            }
            return { retained, error };
          }),
        );
        for (const result of results) {
          expect(result.retained).toBeLessThanOrEqual(512 * 1024);
          expect(result.error).toBeInstanceOf(SSHError);
          expect(result.error).toMatchObject({
            code: "ERR_SSH_OUTPUT_LIMIT",
            phase: "io",
          });
        }
      } finally {
        await ssh.close();
      }
    },
    15_000,
  );

  test("spawn may observe exit before buffered output is consumed", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("printf tail; exit 3");
      expect(await proc.exited).toEqual({ type: "exit", code: 3 });
      expect(new TextDecoder().decode(await readAll(proc.stdout))).toBe("tail");
      await proc.closed;
    } finally {
      await ssh.close();
    }
  });

  test("awaiting closed also settles the visible exit status", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("exit 7");
      await proc.closed;
      expect(proc.exitCode).toBe(7);
    } finally {
      await ssh.close();
    }
  });

  test("spawn cancellation is idempotent and leaves the parent connection usable", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
      const first = proc.cancel();
      const second = proc.cancel();
      expect(first).toBe(second);
      await first;
      await proc.closed;
      await expect(proc.exited).rejects.toMatchObject({
        code: "ERR_SSH_ABORTED",
        phase: "exec",
      });

      const result = await ssh.exec("printf still-ready");
      expect(result.text()).toBe("still-ready");
    } finally {
      await ssh.close();
    }
  });

  test("collecting a running process releases its SSH channel", async () => {
    const ssh = await connectedClient({
      maxChannels: 1,
      queueTimeoutMs: 500,
    });
    try {
      await (async () => {
        await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
      })();

      for (let i = 0; i < 10; i++) {
        Bun.gc(true);
        await new Promise(resolve => setImmediate(resolve));
      }

      expect((await ssh.exec("printf reusable")).text()).toBe("reusable");
    } finally {
      await ssh.close({ force: true });
    }
  });

  test("spawn timeout remains active after spawn resolves", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("sleep 30", {
        stdout: "ignore",
        stderr: "ignore",
        timeoutMs: 100,
      });
      await expect(proc.exited).rejects.toMatchObject({
        code: "ERR_SSH_TIMEOUT",
        phase: "exec",
      });
      await proc.closed;

      const result = await ssh.exec("printf after-timeout");
      expect(result.text()).toBe("after-timeout");
    } finally {
      await ssh.close();
    }
  });

  test("spawn delivers a signal to the remote process", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("trap 'printf term; exit 0' TERM; printf ready; while :; do :; done", {
        stdout: "pipe",
        stderr: "ignore",
      });
      const reader = proc.stdout!.getReader();
      let output = "";
      try {
        while (!output.includes("ready")) {
          const { done, value } = await reader.read();
          if (done) {
            throw new Error(`remote process exited before ready: ${output}`);
          }
          output += new TextDecoder().decode(value);
        }
        expect(output).toBe("ready");

        await proc.sendSignal("TERM");
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }
          output += new TextDecoder().decode(value);
        }
      } finally {
        reader.releaseLock();
      }
      expect(output).toBe("readyterm");
      expect(await proc.exited).toEqual({ type: "exit", code: 0 });
      await proc.closed;
    } finally {
      await ssh.close();
    }
  });

  test("cancelling one output reader discards only that branch", async () => {
    const ssh = await connectedClient();
    try {
      const proc = await ssh.spawn("head -c 1048576 /dev/zero | tr '\\0' x; printf stderr >&2");
      await proc.stdout!.cancel();
      expect(new TextDecoder().decode(await readAll(proc.stderr))).toBe("stderr");
      expect(await proc.exited).toEqual({ type: "exit", code: 0 });
      await proc.closed;
    } finally {
      await ssh.close();
    }
  });

  test("close waits for active spawned channels within its grace period", async () => {
    const ssh = await connectedClient();
    const proc = await ssh.spawn("sleep 0.2; printf finished");
    const closing = ssh.close({ gracePeriodMs: 2_000 });
    expect(ssh.state).toBe("closing");
    expect(new TextDecoder().decode(await readAll(proc.stdout))).toBe("finished");
    expect(await proc.exited).toEqual({ type: "exit", code: 0 });
    expect(await closing).toEqual({ forced: false });
    await proc.closed;
    expect(ssh.state).toBe("closed");
  });

  test("force close stops waiting for active spawned channels", async () => {
    const ssh = await connectedClient();
    const proc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
    const started = performance.now();
    expect(await ssh.close({ force: true })).toEqual({ forced: true });
    expect(performance.now() - started).toBeLessThan(1_000);
    await proc.closed;
    await expect(proc.exited).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
      phase: "exec",
    });
    expect(ssh.state).toBe("closed");
    expect(await ssh.closed).toEqual({ reason: "local", forced: true });
  });

  test("a later close call cannot extend the first grace deadline", async () => {
    const ssh = await connectedClient();
    const proc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
    const first = ssh.close({ gracePeriodMs: 200 });
    const second = ssh.close({ gracePeriodMs: 5_000 });
    expect(second).toBe(first);

    const started = performance.now();
    expect(await first).toEqual({ forced: true });
    expect(performance.now() - started).toBeLessThan(1_500);
    expect(await second).toEqual({ forced: true });
    await proc.closed;
    await expect(proc.exited).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
      phase: "exec",
    });
  });

  test("a later force close shortens an earlier grace deadline", async () => {
    const ssh = await connectedClient();
    const proc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
    const first = ssh.close({ gracePeriodMs: 5_000 });
    const second = ssh.close({ force: true });
    expect(second).toBe(first);

    const started = performance.now();
    expect(await first).toEqual({ forced: true });
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(await second).toEqual({ forced: true });
    await proc.closed;
    await expect(proc.exited).rejects.toMatchObject({
      code: "ERR_SSH_ABORTED",
      phase: "exec",
    });
  });

  test("spawned channels obey channel and pending-operation limits", async () => {
    const ssh = await connectedClient({
      maxChannels: 1,
      maxPendingOperations: 1,
      queueTimeoutMs: 75,
    });
    try {
      const proc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
      const queued = ssh.exec("printf queued");
      await expect(ssh.exec("printf rejected")).rejects.toMatchObject({
        code: "ERR_SSH_QUEUE_FULL",
        phase: "queue",
      });

      await proc.cancel();
      expect((await queued).text()).toBe("queued");

      const timeoutProc = await ssh.spawn("sleep 30", { stdout: "ignore", stderr: "ignore" });
      await expect(ssh.exec("true")).rejects.toMatchObject({
        code: "ERR_SSH_QUEUE_TIMEOUT",
        phase: "queue",
      });
      await timeoutProc.cancel();
    } finally {
      await ssh.close();
    }
  });

  test("observes a peer disconnect and settles the terminal state", async () => {
    const victim = await connectedClient();
    const killer = await connectedClient();
    try {
      const serverPid = (await victim.exec("printf '%s' $PPID")).text();
      expect(serverPid).toMatch(/^\d+$/);

      await killer.exec(`kill -KILL ${serverPid}`);
      expect(await victim.closed).toEqual({ reason: "peer", forced: false });
      expect(victim.state).toBe("closed");
      expect(await victim.close()).toEqual({ forced: false });
      await expect(victim.exec("true")).rejects.toMatchObject({
        code: "ERR_SSH_CLOSED",
        phase: "exec",
      });
      expect((await killer.exec("printf still-ready")).text()).toBe("still-ready");
    } finally {
      await killer.close();
    }
  });

  test("channel connection loss marks the parent connection terminal", async () => {
    const ssh = await connectedClient();
    const error = await ssh.exec("kill -KILL $PPID", { timeoutMs: 0 }).catch(error => error);
    expect(error).toBeInstanceOf(SSHError);
    expect(error.code).toBe("ERR_SSH_CONNECTION_LOST");
    expect(await ssh.closed).toEqual({ reason: "peer", forced: false });
    expect(ssh.state).toBe("closed");
  });
});
