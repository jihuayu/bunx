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
   * The terminal status reported for a remote command.
   *
   * `unknown` means the server did not provide a trustworthy exit status.
   */
  type ExitStatus =
    { type: "exit"; code: number } | { type: "signal"; signal: string; coreDumped: boolean } | { type: "unknown" };

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
   * Data accepted as standard input for an SSH command.
   */
  type SSHInput = string | Uint8Array<ArrayBufferLike> | ArrayBuffer | Blob | ReadableStream<Uint8Array>;

  /**
   * Options shared by SSH operations.
   */
  interface OperationOptions {
    /** Cancels this operation without closing the SSH connection. */
    signal?: AbortSignal | undefined;

    /**
     * The operation deadline in milliseconds. `0` disables only this
     * operation's deadline.
     */
    timeoutMs?: number | undefined;
  }

  /**
   * Options for {@link SSH.exec}.
   */
  interface ExecOptions extends OperationOptions {
    /**
     * Standard input. When omitted, Bun sends EOF immediately.
     */
    stdin?: SSHInput | undefined;

    /**
     * Reject non-zero exits and signal exits with `ERR_SSH_EXIT`.
     *
     * @default false
     */
    check?: boolean | undefined;

    /**
     * Maximum combined stdout and stderr bytes to retain.
     *
     * @default 8 * 1024 * 1024
     */
    maxOutputBytes?: number | undefined;
  }

  /**
   * The fully buffered result of {@link SSH.exec}.
   */
  interface SSHResult {
    readonly stdout: Uint8Array<ArrayBufferLike>;
    readonly stderr: Uint8Array<ArrayBufferLike>;
    readonly status: ExitStatus;

    /** The exit code, or `null` when the status is a signal or unknown. */
    readonly exitCode: number | null;

    /** Monotonic wall-clock duration of the complete operation. */
    readonly durationMs: number;

    /** Whether the remote command was observed to finish. */
    readonly remoteExecution: RemoteExecution;

    /** Decode stdout as UTF-8 with replacement for malformed sequences. */
    text(): string;

    /** Parse {@link text} as JSON. */
    json(): unknown;
  }

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
   * Options for {@link SSH.connect}.
   */
  interface SSHConnectOptions {
    /** Cancels this caller's wait for the connection. */
    signal?: AbortSignal | undefined;
  }

  /**
   * Options for {@link SSH.close}.
   */
  interface SSHCloseOptions {
    /**
     * Stop waiting for a graceful disconnect immediately.
     *
     * @default false
     */
    force?: boolean | undefined;

    /**
     * How long to wait for a graceful disconnect, in milliseconds.
     *
     * @default 5_000
     */
    gracePeriodMs?: number | undefined;
  }

  /**
   * The result of closing an SSH client.
   */
  interface SSHCloseResult {
    /** Whether Bun stopped waiting for a graceful disconnect. */
    readonly forced: boolean;
  }

  /**
   * The terminal state of an SSH client.
   */
  interface SSHClosed {
    /** Who initiated the terminal transition. */
    readonly reason: "local" | "peer" | "failure";

    /** Whether closing required a forced local disconnect. */
    readonly forced: boolean;

    /** The terminal connection failure, when `reason` is `"failure"`. */
    readonly error?: SSHError | undefined;
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

    /** The exit status observed when an exec error carries one. */
    readonly status?: ExitStatus | undefined;

    /** Bounded stdout captured before an exec error. */
    readonly stdout?: Uint8Array<ArrayBufferLike> | undefined;

    /** Bounded stderr captured before an exec error. */
    readonly stderr?: Uint8Array<ArrayBufferLike> | undefined;
  }

  /**
   * A Bun-native SSH client.
   *
   * The constructor validates and snapshots its options synchronously. It does
   * not resolve DNS, open a socket, read a Blob, or invoke a secret provider.
   */
  class SSH implements AsyncDisposable {
    constructor(options: SSHOptions);

    /** The current connection state. */
    readonly state: SSHState;

    /** Connection details after the client is ready, otherwise `null`. */
    readonly info: SSHConnectionInfo | null;

    /**
     * Resolves when the client reaches a terminal state.
     *
     * This promise never rejects. Observe operation failures through their
     * returned promises or through `close()`.
     */
    readonly closed: Promise<SSHClosed>;

    /**
     * Establish and authenticate the connection.
     *
     * Calling this while ready returns immediately, and concurrent calls share
     * one connection attempt. A client cannot reconnect after `close()` or a
     * terminal failure.
     */
    connect(options?: SSHConnectOptions): Promise<void>;

    /**
     * Execute one raw command in a dedicated SSH channel.
     *
     * Calling this method while the client is idle connects and authenticates
     * first. Concurrent commands share the connection and are admitted by the
     * configured FIFO channel queue.
     */
    exec(command: string, options?: ExecOptions): Promise<SSHResult>;

    /**
     * Close the SSH connection.
     *
     * Closing an idle client performs no network I/O. Concurrent calls share
     * one close operation.
     */
    close(options?: SSHCloseOptions): Promise<SSHCloseResult>;

    /** Close the connection using the same bounded path as {@link SSH.close}. */
    [Symbol.asyncDispose](): Promise<void>;
  }
}
