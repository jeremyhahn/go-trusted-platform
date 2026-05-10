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

package nexus

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/keys"
	knownhosts "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/session"
	filestorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage/file"
	secure "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
)

const vendorName = "cisco-nexus"

// hostKeyOwnerScope is the scope under which Nexus host-key pins are
// stored. Switches are infrastructure assets, so service scope is the
// natural fit; the switch ID acts as the owner so each switch's pin is
// addressed independently.
const hostKeyOwnerScope = scope.Service

func init() {
	fabric.RegisterDriver(vendorName, NewDriver)
}

// Result captures the outcome of running a single NX-OS command on the
// switch. It is the protocol-shaped output owned by the driver and
// exposed to executor implementations and tests.
type Result struct {
	// Command is the NX-OS command line that was executed.
	Command string

	// Stdout is the captured standard output.
	Stdout string

	// Stderr is the captured standard error.
	Stderr string

	// Err is the per-command error, if any. nil indicates success.
	Err error
}

// Executor abstracts SSH command execution for testability. The real
// implementation is sessionExecutor (driver-internal); tests inject
// their own mockExecutor.
type Executor interface {
	Execute(ctx context.Context, command string) (stdout string, stderr string, err error)
	ExecuteBatch(ctx context.Context, commands []string) ([]Result, error)
}

// nexusDriver implements fabric.Driver for Cisco Nexus NX-OS switches.
type nexusDriver struct {
	config    fabric.SwitchConfig
	logger    *slog.Logger
	sshSess   session.Session
	executor  Executor
	connected atomic.Bool
}

// NewDriver creates a new Nexus fabric driver for the given switch config.
func NewDriver(cfg fabric.SwitchConfig, logger *slog.Logger) (fabric.Driver, error) {
	if cfg.MgmtIP == "" {
		return nil, ErrInvalidConfig{Reason: "mgmt-ip is required"}
	}

	return &nexusDriver{
		config: cfg,
		logger: logger,
	}, nil
}

// NewDriverWithExecutor creates a nexus driver with an injected executor
// for testing purposes.
func NewDriverWithExecutor(cfg fabric.SwitchConfig, logger *slog.Logger, exec Executor) fabric.Driver {
	return &nexusDriver{
		config:   cfg,
		logger:   logger,
		executor: exec,
	}
}

// Connect establishes an SSH session to the Nexus switch. The session
// is built on top of the xkms enclave-backed key + pinned host-key
// stack: the SSH private key is sealed into a secure.Buffer before
// being parsed, and host-key verification is rooted in a
// known_hosts.BackendStore — there is no trust-on-first-use path.
func (d *nexusDriver) Connect(ctx context.Context) error {
	if d.connected.Load() {
		return nil
	}

	// If an executor was injected (testing), mark connected and return.
	if d.executor != nil {
		d.connected.Store(true)
		return nil
	}

	if d.config.SSHKeyPath == "" {
		return ErrInvalidConfig{Reason: "ssh-key-path is required"}
	}
	if d.config.KnownHostsPath == "" {
		return ErrInvalidConfig{Reason: "known-hosts-path is required"}
	}

	key, err := loadSSHKey(ctx, d.config.SSHKeyPath)
	if err != nil {
		return ErrSSHKeyLoad{Path: d.config.SSHKeyPath, Cause: err}
	}

	hosts, err := newKnownHostsStore(d.config.KnownHostsPath)
	if err != nil {
		key.Destroy()
		return ErrSSHKeyLoad{Path: d.config.KnownHostsPath, Cause: err}
	}

	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            d.config.MgmtIP,
		Port:            d.config.SSHPort,
		User:            d.config.SSHUser,
		Key:             key,
		HostKeyScope:    hostKeyOwnerScope,
		HostKeyOwner:    d.config.ID,
		KnownHostsStore: hosts,
	})
	if err != nil {
		// Dial does not consume Key on the error path; the caller owns
		// destruction.
		key.Destroy()
		return ErrCommandExec{Command: "connect", Cause: err}
	}

	d.sshSess = sess
	d.executor = &sessionExecutor{sess: sess}
	d.connected.Store(true)

	d.logger.Info("nexus: connected",
		slog.String("switch", d.config.ID),
		slog.String("host", d.config.MgmtIP))

	return nil
}

// Close releases the SSH session.
func (d *nexusDriver) Close() error {
	d.connected.Store(false)
	if d.sshSess != nil {
		err := d.sshSess.Close()
		d.sshSess = nil
		return err
	}
	return nil
}

// Ping verifies the connection by running a lightweight command.
func (d *nexusDriver) Ping(ctx context.Context) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}
	stdout, _, err := d.executor.Execute(ctx, "show version | head 1")
	if err != nil {
		return ErrCommandExec{Command: "ping", Cause: err}
	}
	if containsError(stdout) {
		return ErrCommandExec{Command: "ping", Output: stdout, Cause: err}
	}
	return nil
}

// EnsureVLAN creates a VLAN if it does not already exist on the switch.
func (d *nexusDriver) EnsureVLAN(ctx context.Context, vlan uint16, name string) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}

	// Check if VLAN already exists.
	stdout, _, err := d.executor.Execute(ctx, showVLANCommand(vlan))
	if err == nil && stdout != "" {
		if _, found := parseShowVLAN(stdout, vlan); found {
			d.logger.Debug("nexus: vlan already exists",
				slog.String("switch", d.config.ID),
				slog.Uint64("vlan", uint64(vlan)))
			return nil
		}
	}

	// Create the VLAN.
	cmds := createVLANCommands(vlan, name)
	return d.executeBatch(ctx, cmds, "EnsureVLAN")
}

// EnsureVNI maps a VNI to a VLAN on the NVE interface if not already present.
func (d *nexusDriver) EnsureVNI(ctx context.Context, vni uint32, vlan uint16) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}

	// Check if VNI mapping already exists.
	stdout, _, err := d.executor.Execute(ctx, showNVEVNICommand())
	if err == nil && parseShowNVEVNI(stdout, vni) {
		d.logger.Debug("nexus: vni already mapped",
			slog.String("switch", d.config.ID),
			slog.Uint64("vni", uint64(vni)))
		return nil
	}

	cmds := createVNICommands(vni, vlan)
	return d.executeBatch(ctx, cmds, "EnsureVNI")
}

// EnsureLAG configures a link aggregation group if not already present.
func (d *nexusDriver) EnsureLAG(ctx context.Context, lag fabric.LAGConfig) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}

	// Check if port-channel already exists.
	stdout, _, err := d.executor.Execute(ctx, showPortChannelSummaryCommand())
	if err == nil && parseShowPortChannelSummary(stdout, lag.PortChannelID) {
		d.logger.Debug("nexus: port-channel already exists",
			slog.String("switch", d.config.ID),
			slog.Uint64("port-channel", uint64(lag.PortChannelID)))
		return nil
	}

	// Collect member ports that belong to this switch.
	var memberPorts []string
	for _, m := range lag.Members {
		if m.SwitchID == d.config.ID {
			memberPorts = append(memberPorts, m.Port)
		}
	}

	cmds := createLAGCommands(lag.PortChannelID, memberPorts, lag.LACPMode, lag.MCLAG)
	return d.executeBatch(ctx, cmds, "EnsureLAG")
}

// SetPortAccess configures a port in access mode with the given VLAN.
func (d *nexusDriver) SetPortAccess(ctx context.Context, port fabric.PortRef, vlan uint16) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}

	// Check current config for idempotency.
	stdout, _, err := d.executor.Execute(ctx, showRunningInterfaceCommand(port.Port))
	if err == nil {
		currentVLAN := parseShowRunningInterface(stdout)
		if currentVLAN == vlan && strings.Contains(stdout, "switchport mode access") {
			d.logger.Debug("nexus: port already in access mode with correct vlan",
				slog.String("switch", d.config.ID),
				slog.String("port", port.Port),
				slog.Uint64("vlan", uint64(vlan)))
			return nil
		}
	}

	cmds := setPortAccessCommands(port.Port, vlan)
	return d.executeBatch(ctx, cmds, "SetPortAccess")
}

// SetPortTrunk configures a port in trunk mode with the allowed VLANs
// and native VLAN.
func (d *nexusDriver) SetPortTrunk(ctx context.Context, port fabric.PortRef, allowed []uint16, native uint16) error {
	if !d.connected.Load() {
		return ErrNotConnected{}
	}

	cmds := setPortTrunkCommands(port.Port, allowed, native)
	return d.executeBatch(ctx, cmds, "SetPortTrunk")
}

// executeBatch runs a batch of NX-OS commands and checks for errors.
func (d *nexusDriver) executeBatch(ctx context.Context, cmds []string, operation string) error {
	results, err := d.executor.ExecuteBatch(ctx, cmds)
	if err != nil {
		return ErrCommandExec{
			Command: operation,
			Cause:   err,
		}
	}

	for _, r := range results {
		if r.Err != nil {
			return ErrCommandExec{
				Command: r.Command,
				Output:  r.Stderr,
				Cause:   r.Err,
			}
		}
		if containsError(r.Stdout) {
			return ErrCommandExec{
				Command: r.Command,
				Output:  r.Stdout,
				Cause:   ErrParseOutput{Command: r.Command, Reason: "error in output"},
			}
		}
	}

	d.logger.Debug("nexus: operation complete",
		slog.String("switch", d.config.ID),
		slog.String("operation", operation))

	return nil
}

// sessionExecutor is the production Executor. It runs each command as
// its own SSH exec channel against the session.Session — this matches
// NX-OS's preferred non-interactive command model and keeps each
// command's stdout/stderr cleanly separated.
type sessionExecutor struct {
	sess session.Session
}

// Execute implements Executor.Execute.
func (e *sessionExecutor) Execute(ctx context.Context, command string) (string, string, error) {
	stdout, stderr, err := e.sess.Run(ctx, command)
	return string(stdout), string(stderr), err
}

// ExecuteBatch implements Executor.ExecuteBatch. Per-command failures
// are surfaced inside the returned []Result; only an outer error
// (e.g., context cancellation between commands) returns a non-nil
// error.
func (e *sessionExecutor) ExecuteBatch(ctx context.Context, commands []string) ([]Result, error) {
	results := make([]Result, 0, len(commands))
	for _, cmd := range commands {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		stdout, stderr, runErr := e.sess.Run(ctx, cmd)
		results = append(results, Result{
			Command: cmd,
			Stdout:  string(stdout),
			Stderr:  string(stderr),
			Err:     runErr,
		})
	}
	return results, nil
}

// loadSSHKey reads the PEM-encoded private key at path, seals it into
// an enclave-backed Buffer, and parses it via keys.ParsePEM. The
// returned *keys.Key owns its enclave; callers MUST Destroy on any
// failure path that does not hand the key to a Session.
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

// newKnownHostsStore constructs a known_hosts.BackendStore rooted in
// the directory containing the configured KnownHostsPath. The legacy
// flat OpenSSH known_hosts file is not consumed by the new
// known_hosts API (which expects per-pin envelopes); operators must
// pre-populate the directory with pin envelopes via the xkms tooling.
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

// Compile-time interface check.
var _ fabric.Driver = (*nexusDriver)(nil)
