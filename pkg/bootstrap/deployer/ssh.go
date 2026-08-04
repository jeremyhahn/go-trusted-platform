// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package deployer

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/keys"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/session"
	filestorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage/file"
)

// hostKeyScope is the ownership scope under which deployer host-key pins are
// stored. The deployer connects to stable infrastructure (the jumpbox /
// deployer host), so service scope is the natural fit — this mirrors
// pkg/switch's SSH executor so a deployer host's pin is addressed the same
// way across both code paths.
const hostKeyScope = scope.Service

// copyFileMode is the permission applied to streamed uploads. ISO images,
// container tars, and config sidecars are served read-only over HTTP/SMB or
// loaded by the container runtime, so 0644 (deterministic, independent of the
// remote umask) is the right default.
const copyFileMode = 0o644

// SSHClient streams files and runs commands on a deployer host over an xkms
// enclave-backed, host-key-pinned SSH session. The private key lives sealed
// in a secure enclave and host-key verification is rooted in a known_hosts
// BackendStore — there is no trust-on-first-use path.
type SSHClient struct {
	host           string
	port           int
	user           string
	keyPath        string
	knownHostsPath string

	sess      session.Session
	connected atomic.Bool
}

// NewSSHClient constructs an SSHClient for the deployer host. The key at
// keyPath is loaded and the connection established lazily by Connect, so
// construction performs no I/O.
//
// It fails closed when knownHostsPath is empty: deployer SSH requires pinned
// host keys and never accepts a host key blindly. Operators pre-populate the
// known_hosts directory with pin envelopes via the xkms tooling, exactly as
// for the switch and fabric/nexus drivers.
func NewSSHClient(host string, port int, user, keyPath, knownHostsPath string) (*SSHClient, error) {
	if host == "" {
		return nil, ErrInvalidDeployConfig{Field: "host", Reason: "must not be empty"}
	}
	if user == "" {
		return nil, ErrInvalidDeployConfig{Field: "user", Reason: "must not be empty"}
	}
	if keyPath == "" {
		return nil, ErrInvalidDeployConfig{Field: "ssh_key_path", Reason: "must not be empty"}
	}
	// Fail closed: deployer SSH requires pinned host keys. There is no
	// trust-on-first-use fallback and host keys are never accepted blindly.
	if knownHostsPath == "" {
		return nil, ErrInvalidDeployConfig{
			Field:  "known_hosts_path",
			Reason: "must be set; deployer SSH requires pinned host keys",
		}
	}
	if port == 0 {
		port = DefaultSSHPort
	}
	return &SSHClient{
		host:           host,
		port:           port,
		user:           user,
		keyPath:        keyPath,
		knownHostsPath: knownHostsPath,
	}, nil
}

// Connect loads the enclave-backed key, builds the pinned known_hosts store,
// and performs the TCP dial + SSH handshake + host-key verification in a
// single session.Dial call. The key is sealed into a secure buffer before
// parsing and its ownership transfers to the session on success; on any
// failure path the key is destroyed before returning.
func (c *SSHClient) Connect(ctx context.Context) error {
	key, err := loadSSHKey(ctx, c.keyPath)
	if err != nil {
		return err
	}

	hosts, err := newKnownHostsStore(c.knownHostsPath)
	if err != nil {
		key.Destroy()
		return ErrSSHConnect{Host: c.host, Port: c.port, Cause: err}
	}

	// session.Dial takes ownership of key on success; on the error path the
	// key remains ours to destroy.
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            c.host,
		Port:            c.port,
		User:            c.user,
		Key:             key,
		HostKeyScope:    hostKeyScope,
		HostKeyOwner:    c.host,
		KnownHostsStore: hosts,
	})
	if err != nil {
		key.Destroy()
		return ErrSSHConnect{Host: c.host, Port: c.port, Cause: err}
	}

	c.sess = sess
	c.connected.Store(true)
	return nil
}

// Run executes a command on the remote host and returns stdout. On a
// non-zero remote exit the captured output (stderr, falling back to stdout)
// is surfaced inside the returned ErrSSHCommand.
func (c *SSHClient) Run(ctx context.Context, command string) (string, error) {
	if !c.connected.Load() {
		return "", ErrSSHNotConnected{Host: c.host, Port: c.port}
	}

	stdout, stderr, err := c.sess.Run(ctx, command)
	if err != nil {
		output := string(stderr)
		if output == "" {
			output = string(stdout)
		}
		return output, ErrSSHCommand{Command: command, Output: output, Cause: err}
	}
	return string(stdout), nil
}

// CopyFile copies a local file to a remote path using SSH cat with base64
// encoding.
//
// This implementation reads the entire file into memory and embeds it in the
// command line, so it's only safe for files up to ~64 KiB (manifest YAML,
// configs, scripts). For multi-megabyte payloads use CopyFileStream which
// pipes the raw bytes through the SSH session's stdin and has no shell argv
// length limit.
func (c *SSHClient) CopyFile(ctx context.Context, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return ErrFileRead{Path: localPath, Cause: err}
	}

	// Use base64 encoding to safely transfer binary content via shell command.
	encoded := base64.StdEncoding.EncodeToString(data)
	cmd := "echo '" + encoded + "' | base64 -d > " + remotePath

	if _, err := c.Run(ctx, cmd); err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}
	return nil
}

// CopyFileStream streams a local file to a remote path over the
// host-key-verified session via session.Upload. Unlike CopyFile it does not
// buffer the whole file in memory and has no argv length limit, so it's the
// right tool for ISO-sized payloads (hundreds of MB to multiple GB).
//
// Atomicity is provided by Upload: the payload is written to
// "<remotePath>.partial", chmod'd, then atomically renamed onto remotePath
// on the same filesystem.
//
// Idempotency is up to the caller — this method always uploads. The
// orchestrator's ISO stager compares the local sha256 against a sidecar
// metadata file written next to the staged payload and skips this call on
// match.
func (c *SSHClient) CopyFileStream(ctx context.Context, localPath, remotePath string) error {
	if !c.connected.Load() {
		return ErrSSHNotConnected{Host: c.host, Port: c.port}
	}

	src, err := os.Open(localPath)
	if err != nil {
		return ErrFileRead{Path: localPath, Cause: err}
	}
	defer src.Close()

	if err := c.sess.Upload(ctx, src, remotePath, copyFileMode); err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}
	return nil
}

// StatRemote returns the size and modification time of a remote file by
// running `stat -c '%s %Y' <path>` and parsing the result. Used by the
// orchestrator to skip ISO uploads when the remote file already matches.
//
// Returns ErrRemoteFileNotFound (wrapped via ErrFileRead) when the remote
// file doesn't exist — callers should treat that as "needs upload".
func (c *SSHClient) StatRemote(ctx context.Context, remotePath string) (size int64, mtime int64, err error) {
	out, runErr := c.Run(ctx, "stat -c '%s %Y' '"+remotePath+"' 2>/dev/null || echo MISSING")
	if runErr != nil {
		return 0, 0, ErrFileRead{Path: remotePath, Cause: runErr}
	}
	out = strings.TrimSpace(out)
	if out == "MISSING" || out == "" {
		return 0, 0, ErrRemoteFileNotFound{Path: remotePath}
	}
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return 0, 0, ErrFileRead{Path: remotePath, Cause: ErrUnexpectedStatOutput{Output: out}}
	}
	size, parseErr := strconv.ParseInt(parts[0], 10, 64)
	if parseErr != nil {
		return 0, 0, ErrFileRead{Path: remotePath, Cause: parseErr}
	}
	mtime, parseErr = strconv.ParseInt(parts[1], 10, 64)
	if parseErr != nil {
		return 0, 0, ErrFileRead{Path: remotePath, Cause: parseErr}
	}
	return size, mtime, nil
}

// Close terminates the SSH session, which destroys the enclave-backed key.
// Calling Close on a never-connected client is a no-op.
func (c *SSHClient) Close() error {
	if c.sess != nil && c.connected.Load() {
		c.connected.Store(false)
		err := c.sess.Close()
		c.sess = nil
		return err
	}
	return nil
}

// IsConnected returns whether the SSH client has an established session.
func (c *SSHClient) IsConnected() bool {
	return c.connected.Load()
}

// loadSSHKey reads the PEM-encoded private key at path, seals it into an
// enclave-backed Buffer, and parses it via keys.ParsePEM. The returned
// *keys.Key owns its enclave; callers MUST Destroy it on any failure path
// that does not hand the key to a Session.
func loadSSHKey(ctx context.Context, path string) (*keys.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrSSHKeyRead{Path: path, Cause: err}
	}
	buf, err := secure.NewBufferFromBytes(data)
	if err != nil {
		return nil, ErrSSHKeyParse{Path: path, Cause: err}
	}
	defer buf.Destroy()
	key, err := keys.ParsePEM(ctx, buf, nil)
	if err != nil {
		return nil, ErrSSHKeyParse{Path: path, Cause: err}
	}
	return key, nil
}

// newKnownHostsStore constructs a known_hosts BackendStore rooted in the
// directory containing the configured knownHostsPath. The legacy flat
// OpenSSH known_hosts file is not consumed by the known_hosts API (which
// expects per-pin envelopes); operators pre-populate the directory with pin
// envelopes via the xkms tooling.
func newKnownHostsStore(path string) (knownhosts.Store, error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	backend, err := filestorage.New(dir)
	if err != nil {
		return nil, err
	}
	return knownhosts.NewBackendStore(backend)
}
