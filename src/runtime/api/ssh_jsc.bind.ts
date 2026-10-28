import * as b from "../../codegen/bindgen-lib.ts";

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
      maxChannels: b.usize,
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
