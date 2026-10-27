declare module "bun" {
  /**
   * The lifecycle state of an SSH connection.
   */
  type SSHState = "idle" | "connecting" | "ready" | "closing" | "closed" | "failed";

  /**
   * The connection stage in which an SSH error occurred.
   */
  type SSHPhase =
    "config" | "dns" | "tcp" | "handshake" | "host-key" | "auth" | "queue" | "channel" | "exec" | "io" | "close";

  /**
   * Whether a remote command may have started.
   *
   * `may-have-started` means the request might have reached the server. Bun does
   * not retry an operation in this state because doing so could repeat side
   * effects.
   */
  type RemoteExecution = "not-started" | "may-have-started" | "exit-observed";

  /**
   * A password or passphrase accepted by Bun.SSH.
   */
  type SSHSecret = string | Uint8Array<ArrayBufferLike>;

  /**
   * An unencrypted SSH private key accepted by Bun.SSH.
   */
  type SSHKey = Uint8Array<ArrayBufferLike> | Blob;

  /**
   * A secret value, or a function that resolves it when it is needed.
   *
   * Bun.SSH does not call the function from the constructor. The abort signal
   * is aborted when the authentication attempt no longer needs the secret.
   */
  type SecretSource<T> = T | ((context: { signal: AbortSignal }) => T | Promise<T>);

  /**
   * Authentication methods accepted by Bun.SSH.
   */
  type SSHAuth =
    | {
        /** Use password authentication. */
        type: "password";
        /** The password, or a function that resolves it. */
        password: SecretSource<SSHSecret>;
      }
    | {
        /** Use public key authentication. */
        type: "privateKey";
        /** The private key bytes or file, or a function that resolves them. */
        key: SecretSource<SSHKey>;
        /** The passphrase for an encrypted private key. */
        passphrase?: SecretSource<SSHSecret> | undefined;
      };

  /**
   * Strict server identity verification. Bun.SSH has no implicit trust policy.
   */
  type SSHHostKeyPolicy =
    | {
        /** Match the server against an OpenSSH known_hosts file. */
        type: "knownHosts";
        /** The known_hosts contents. Bun reads the Blob when it connects. */
        file: Blob;
      }
    | {
        /** Accept only one of the listed SHA-256 host key fingerprints. */
        type: "pinned";
        /** One or more pinned SHA-256 fingerprints. */
        sha256: readonly [string, ...string[]];
      };

  /**
   * Options for a Bun.SSH client.
   */
  interface SSHOptions {
    /** The server hostname or IP address. */
    hostname: string;

    /**
     * The TCP port.
     *
     * @default 22
     */
    port?: number | undefined;

    /** The username sent to the server. */
    username: string;

    /** Required strict server identity verification. */
    hostKey: SSHHostKeyPolicy;

    /** The authentication method. Bun.SSH never falls back to another method. */
    auth: SSHAuth;

    /**
     * The DNS, TCP, handshake, and host verification deadline in milliseconds.
     *
     * @default 10_000
     */
    connectTimeoutMs?: number | undefined;

    /**
     * The authentication deadline in milliseconds.
     *
     * @default 30_000
     */
    authenticationTimeoutMs?: number | undefined;

    /**
     * The maximum number of open SSH channels on this connection.
     *
     * @default 8
     */
    maxChannels?: number | undefined;

    /**
     * The maximum number of operations waiting for a channel.
     *
     * @default 64
     */
    maxPendingOperations?: number | undefined;

    /**
     * How long an operation may wait in the queue, in milliseconds.
     *
     * @default 30_000
     */
    queueTimeoutMs?: number | undefined;
  }

  /**
   * Information about an established SSH connection.
   */
  interface SSHConnectionInfo {
    readonly hostname: string;
    readonly port: number;
    readonly username: string;
    readonly hostKeyAlgorithm: string;
    readonly hostKeySHA256: string;
    readonly cipherClientToServer: string;
    readonly cipherServerToClient: string;
  }

  /**
   * Stable error codes reported by Bun.SSH.
   */
  type SSHErrorCode =
    | "ERR_SSH_CONFIG"
    | "ERR_SSH_UNSUPPORTED"
    | "ERR_SSH_CONNECT"
    | "ERR_SSH_CONNECT_TIMEOUT"
    | "ERR_SSH_HOST_KEY_UNKNOWN"
    | "ERR_SSH_HOST_KEY_CHANGED"
    | "ERR_SSH_HOST_KEY_REVOKED"
    | "ERR_SSH_HOST_KEY_INVALID"
    | "ERR_SSH_AUTH"
    | "ERR_SSH_AUTH_TIMEOUT"
    | "ERR_SSH_QUEUE_FULL"
    | "ERR_SSH_QUEUE_TIMEOUT"
    | "ERR_SSH_CHANNEL_OPEN"
    | "ERR_SSH_EXEC_REJECTED"
    | "ERR_SSH_PROTOCOL"
    | "ERR_SSH_IO"
    | "ERR_SSH_TIMEOUT"
    | "ERR_SSH_ABORTED"
    | "ERR_SSH_OUTPUT_LIMIT"
    | "ERR_SSH_RESOURCE_LIMIT"
    | "ERR_SSH_CONNECTION_LOST"
    | "ERR_SSH_CLOSED"
    | "ERR_SSH_EXIT"
    | "ERR_SSH_EXIT_UNKNOWN";

  /**
   * An error from Bun.SSH.
   */
  class SSHError extends Error {
    constructor(message: string, options: { code: SSHErrorCode; phase: SSHPhase; cause?: unknown });

    /** The stable error category. */
    readonly code: SSHErrorCode;

    /** The connection stage in which the error occurred. */
    readonly phase: SSHPhase;

    /** A local identifier that correlates this error with an operation. */
    readonly operationId: string;

    /** Whether the remote command may have started. */
    readonly remoteExecution: RemoteExecution;
  }

  /**
   * A Bun-native SSH client.
   *
   * The constructor validates and snapshots its options synchronously. It does
   * not resolve DNS, open a socket, read a Blob, or invoke a secret provider.
   */
  class SSH {
    constructor(options: SSHOptions);

    /** The current connection state. */
    readonly state: SSHState;

    /** Connection details after the client is ready, otherwise `null`. */
    readonly info: SSHConnectionInfo | null;
  }
}
