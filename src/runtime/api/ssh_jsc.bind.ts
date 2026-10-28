import * as b from "../../codegen/bindgen-lib.ts";

/**
 * One process-wide pool for SSH output retained by native channels.
 */
export const SSHBudget = b.class({
  rustPath: "crate::api::ssh_jsc::SSHBudget",
  refCounted: true,
  finalize: true,
  configurable: false,
  construct: {
    args: {
      maxBytes: b.usize,
    },
    capability: "heap",
    throws: true,
  },
});

/**
 * The native SSH transport. Bun.SSH owns all state and callbacks in JS; this
 * object exists so native work can outlive a single host call without retaining
 * a JavaScript value on the Tokio thread.
 */
export const SSHConnection = b.class({
  rustPath: "crate::api::ssh_jsc::SSHConnection",
  refCounted: true,
  finalize: true,
  configurable: false,
  construct: {
    args: {
      hostname: b.string.utf8,
      port: b.u16,
      username: b.string.utf8,
      hostKeyKind: b.string.utf8,
      knownHosts: b.bytes({ from: ["buffer"], held: "copied" }),
      pins: b.array(b.string.utf8.owned).nullable,
      connectTimeoutMs: b.u64,
      outputBudget: SSHBudget,
    },
    capability: "heap",
    throws: true,
  },
  proto: {
    hostname: { getter: b.string.utf8 },
    port: { getter: b.u16 },
    connectTransport: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    isClosed: {
      returns: b.bool,
      capability: "js",
      throws: false,
    },
    authenticatePassword: {
      args: {
        password: b.bytes({ from: ["buffer"], held: "copied" }),
        timeoutMs: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    authenticatePrivateKey: {
      args: {
        key: b.bytes({ from: ["buffer"], held: "copied" }),
        timeoutMs: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    authenticatePrivateKeyWithPassphrase: {
      args: {
        key: b.bytes({ from: ["buffer"], held: "copied" }),
        passphrase: b.bytes({ from: ["buffer"], held: "copied" }),
        timeoutMs: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    close: {
      args: {
        gracePeriodMs: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    execute: {
      args: {
        command: b.bytes({ from: ["buffer"], held: "copied" }),
        stdin: b.bytes({ from: ["buffer"], held: "copied" }),
        timeoutMs: b.u64,
        maxOutputBytes: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    startProcess: {
      rustName: "start_process_js",
      args: {
        command: b.bytes({ from: ["buffer"], held: "copied" }),
        stdinMode: b.string.utf8,
        stdinData: b.bytes({ from: ["buffer"], held: "copied" }),
        captureStdout: b.bool,
        captureStderr: b.bool,
        timeoutMs: b.u64,
      },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    cancelOperation: {
      args: {
        operationId: b.u64,
      },
      returns: b.bool,
      capability: "js",
      throws: false,
    },
  },
});

/** The native side of a spawned SSH process channel. */
export const SSHProcess = b.class({
  rustPath: "crate::api::ssh_jsc::SSHSpawnProcess",
  refCounted: true,
  finalize: true,
  configurable: false,
  proto: {
    readStdout: {
      args: { maxBytes: b.usize },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    readStderr: {
      args: { maxBytes: b.usize },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    discardStdout: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    discardStderr: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    writeStdin: {
      args: { data: b.bytes({ from: ["buffer"], held: "copied" }) },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    closeStdin: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    sendSignal: {
      args: { signal: b.string.utf8 },
      returns: b.any,
      capability: "js",
      throws: true,
    },
    cancel: {
      returns: b.bool,
      capability: "js",
      throws: false,
    },
    waitExit: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    waitClosed: {
      returns: b.any,
      capability: "js",
      throws: true,
    },
    remoteExecution: {
      getter: b.string.utf8,
    },
  },
});
