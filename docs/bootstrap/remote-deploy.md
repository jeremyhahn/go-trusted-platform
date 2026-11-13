# Remote deploy over QUIC

The deployer stages ISO images, container tarballs and config files on a
deploy target and runs commands there. Until now it did that only over SSH
(`deployer.SSHClient`). The QUIC deploy agent
(`pkg/bootstrap/deployer/quicagent`) is the FIPS-native transport that
replaces it (`docs/SPEC.md`, row `remote-deploy`).

## The seam

`pkg/bootstrap/deployer/types.go` exports two interfaces:

| Interface | Methods | Used by |
|-----------|---------|---------|
| `RemoteStager` | `Run`, `CopyFileStream` | the netboot media stager |
| `RemoteHost` | `RemoteStager` plus `Connect`, `Close`, `StatRemote` | the ISO stager |

`deployer.SSHClient` and `quicagent.Client` both satisfy `RemoteHost`
(compile-time assertions in each package). The package-private
`remoteHost` (`netboot_media.go`) and `remoteISOClient`
(`pkg/bootstrap/iso_stager.go`) are aliases of these interfaces, so the
callers take either transport without change.

## The agent

`quicagent.Server` runs on the deploy target; `quicagent.Client` runs in the
deployer.

- **Transport:** QUIC (quic-go), ALPN `gtp-deploy-agent/1`.
- **TLS:** TLS 1.3 only, both ends. The agent requires and verifies a client
  certificate against its `ClientCAs` (`tls.RequireAndVerifyClientCert`);
  the client verifies the agent against its `RootCAs`. A client whose
  certificate does not verify is refused at the handshake, before any
  operation runs.
- **FIPS:** key exchange is limited to P-256 and P-384. TLS 1.3 cipher
  suites are fixed by `crypto/tls`; with `GODEBUG=fips140=on` it keeps to
  AES-GCM.
- **No SSH fallback.** A target that runs the agent is reached only over
  QUIC; a failed connection is an error, never a retry over SSH.

`NewClient` and `NewServer` refuse a TLS configuration without the
certificate and CA pool their side needs (`ErrInvalidTLSConfig`). They
force the TLS version, ALPN and curves themselves, so a caller cannot
weaken them.

## Wire format

Each operation is one bidirectional QUIC stream:

1. the client writes a request frame,
2. for a copy, the client writes exactly `size` raw body bytes,
3. the client closes its send side,
4. the agent writes one response frame and closes the stream.

A frame is a 4-byte big-endian length followed by that many bytes of JSON,
at most 16 MiB.

| Operation | Request | Response |
|-----------|---------|----------|
| `run` | `command` | `stdout`, `stderr`, `exit_code` |
| `copy` | `path`, `size` + body | `size`, `sha256` |
| `stat` | `path` | `size`, `mtime` or `not_found` |

Any response may carry `error` instead; the agent then also stops reading
the stream.

- **Run** executes the command with `/bin/sh -c`, as an SSH session would.
  A non-zero exit gives `quicagent.ErrCommand` with the status and the
  output (stderr, else stdout). Stdout and stderr together may hold
  2 MiB, enforced while the command runs: the write that passes the budget
  kills the command's process group and the response carries
  `quicagent.ErrOutputTooLarge` instead of the output.
- **CopyFileStream** streams the file without buffering it. The client
  sends exactly the size it announced and hashes those same bytes: a file
  that grows during the upload is cut at that size, and one that shrinks
  fails with `quicagent.ErrSourceChanged` before the agent commits it. The agent
  writes a temporary file beside the target, sets mode 0644 and renames it
  into place, so a failed copy never leaves a partial file at the target.
  The client compares the agent's sha256 with its own and returns
  `quicagent.ErrDigestMismatch` when they differ. A missing local file
  gives `deployer.ErrFileRead`.
- **StatRemote** returns size and modification time (Unix seconds), or
  `deployer.ErrRemoteFileNotFound`, the same contract as `SSHClient`.

Operations before `Connect` return `quicagent.ErrNotConnected`.

## Out of scope

- Issuing the agent and deployer certificates. The tests use in-memory test
  certificates; production issuance comes from the platform CA in a later
  slice.
- Installing the agent on a target and choosing the transport from the
  deploy config.
