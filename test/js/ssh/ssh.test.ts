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
  let wrongPinsHostKey: Bun.SSHHostKeyPolicy;

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
});
