import { SSH, SSHError } from "bun";
import { describe, expect, test } from "bun:test";

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
});
