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

package switchmgmt

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/keys"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/session"
	filestorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage/file"
)

// hostKeyScope is the ownership scope under which physical-switch host-key
// pins are stored. Switches are infrastructure assets, so service scope is
// the natural fit; this mirrors pkg/sdn/fabric/nexus so a switch's pin is
// addressed the same way across both code paths.
const hostKeyScope = scope.Service

// sshExecutor runs switch CLI commands over an xkms enclave-backed,
// host-key-pinned SSH session. The session's private key lives sealed in a
// secure enclave and host-key verification is rooted in a known_hosts
// BackendStore — there is no trust-on-first-use path.
type sshExecutor struct {
	sess session.Session
}

// NewSSHExecutor dials the switch over the xkms SSH stack and returns a
// connected executor. The private key at config.SSHKey is sealed into a
// secure.Buffer before parsing, and session.Dial performs the TCP dial, SSH
// handshake, and host-key verification against the pinned known_hosts store
// rooted at config.KnownHostsPath in a single call.
//
// It fails closed when no host-key pins are provisioned: the legacy
// insecure host-key-ignore behaviour is gone. Operators must pre-populate the
// known_hosts directory with pin envelopes via the xkms tooling, exactly as
// for the fabric/nexus driver.
func NewSSHExecutor(ctx context.Context, config *Config) (SSHExecutor, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if config.SSHKey == "" {
		return nil, ErrSSHConnectionFailed{
			Host:  config.Host,
			Cause: ErrInvalidConfig{Field: "ssh_key", Reason: "must be set"},
		}
	}
	// Fail closed: switch SSH requires pinned host keys. There is no
	// trust-on-first-use fallback and host keys are never accepted blindly.
	if config.KnownHostsPath == "" {
		return nil, ErrSSHConnectionFailed{
			Host: config.Host,
			Cause: ErrInvalidConfig{
				Field:  "known_hosts_path",
				Reason: "must be set; switch SSH requires pinned host keys",
			},
		}
	}

	key, err := loadSSHKey(ctx, config.SSHKey)
	if err != nil {
		return nil, ErrSSHConnectionFailed{Host: config.Host, Cause: err}
	}

	hosts, err := newKnownHostsStore(config.KnownHostsPath)
	if err != nil {
		key.Destroy()
		return nil, ErrSSHConnectionFailed{Host: config.Host, Cause: err}
	}

	// session.Dial takes ownership of key on success; on the error path the
	// key remains ours to destroy.
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            config.Host,
		Port:            config.Port,
		User:            config.User,
		Key:             key,
		HostKeyScope:    hostKeyScope,
		HostKeyOwner:    hostKeyOwner(config),
		KnownHostsStore: hosts,
	})
	if err != nil {
		key.Destroy()
		return nil, ErrSSHConnectionFailed{Host: config.Host, Cause: err}
	}

	return &sshExecutor{sess: sess}, nil
}

// Execute runs a single command on the switch and returns its stdout. On a
// non-zero remote exit the captured stderr is surfaced inside the returned
// ErrCommandFailed.
func (s *sshExecutor) Execute(ctx context.Context, command string) (string, error) {
	stdout, stderr, err := s.sess.Run(ctx, command)
	if err != nil {
		return "", ErrCommandFailed{
			Command: command,
			Output:  string(stderr),
			Cause:   err,
		}
	}
	return string(stdout), nil
}

// Close terminates the SSH session, which destroys the enclave-backed key.
func (s *sshExecutor) Close() error {
	if s.sess != nil {
		return s.sess.Close()
	}
	return nil
}

// hostKeyOwner returns the known_hosts pin owner for the switch: the
// configured Name, falling back to Host. This mirrors Service's
// name-or-host keying so a switch's host-key pin is addressed the same way
// the switch itself is registered.
func hostKeyOwner(config *Config) string {
	if config.Name != "" {
		return config.Name
	}
	return config.Host
}

// loadSSHKey reads the PEM-encoded private key at path, seals it into an
// enclave-backed Buffer, and parses it via keys.ParsePEM. The returned
// *keys.Key owns its enclave; callers MUST Destroy it on any failure path
// that does not hand the key to a Session.
func loadSSHKey(ctx context.Context, path string) (*keys.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	buf, err := secure.NewBufferFromBytes(data)
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	return keys.ParsePEM(ctx, buf, nil)
}

// newKnownHostsStore constructs a known_hosts BackendStore rooted in the
// directory containing the configured KnownHostsPath. The legacy flat
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
