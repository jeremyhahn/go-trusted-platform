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

package qemu

import (
	"context"
	"fmt"
	"os"
)

// migrationTLSCredsObjectID is the QOM id used for the destination-side
// tls-creds-x509 migration credentials installed on the receiving QEMU. The
// source references the same logical credentials through migrate-set-parameters
// tls-creds on its own monitor; the id is local to each QEMU process.
const migrationTLSCredsObjectID = "migtls0"

// StartIncoming launches the VM as the destination of a migration. Unlike Start,
// the guest is not booted from its disk: QEMU comes up with "-incoming defer"
// and blocks until a migrate-incoming QMP command supplies the listen URI, so
// the caller can install the migration TLS parameters (tls-creds) BEFORE the
// stream is accepted. The migration channel is therefore never plaintext.
//
// When tlsCredsDir is non-empty a server-endpoint tls-creds-x509 object is added
// on the command line (verify-peer=on, mutual TLS) pointing at a directory that
// holds QEMU's expected server-cert.pem / server-key.pem / ca-cert.pem. The
// returned credentials id (StartIncoming installs it under migrationTLSCredsObjectID)
// is what the caller passes to migrate-set-parameters tls-creds via the QMP
// monitor before issuing migrate-incoming.
//
// StartIncoming reuses buildQEMUCommand so the receiver is byte-for-byte the same
// machine model (CPU, memory, firmware, TPM, disk bus, QMP socket) as a normally
// booted VM; it only appends the migration-specific flags.
func (vm *VM) StartIncoming(ctx context.Context, tlsCredsDir string) (credsID string, err error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.running.Load() {
		return "", ErrVMAlreadyRunning
	}

	// A receiver always boots from disk (block data streams into the fresh
	// image for a cold migration; a shared image is reused for a live one).
	if _, statErr := os.Stat(vm.config.DiskPath); statErr != nil {
		return "", &SentinelCauseError{Sentinel: ErrDiskNotFound, Cause: &MessageError{Msg: fmt.Sprintf("%s", vm.config.DiskPath)}}
	}

	// Clean up any stale QMP socket from a previous run.
	qmpSocketPath := vm.config.GetQMPSocketPath()
	if rmErr := os.Remove(qmpSocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
		vm.logger.Warnf("Failed to remove stale QMP socket: %v", rmErr)
	}

	if nvErr := vm.initializeNVRAM(); nvErr != nil {
		return "", &WrappedError{Msg: "failed to initialize NVRAM", Err: nvErr}
	}

	cmd, buildErr := vm.buildQEMUCommand(ctx, BootModeBoot)
	if buildErr != nil {
		return "", &WrappedError{Msg: "failed to build QEMU command", Err: buildErr}
	}

	// Install the destination-side migration TLS credentials and defer the
	// incoming connection so the QMP monitor can set tls-creds before the
	// stream is accepted.
	if tlsCredsDir != "" {
		credsID = migrationTLSCredsObjectID
		cmd.Args = append(cmd.Args,
			"-object",
			fmt.Sprintf("tls-creds-x509,id=%s,endpoint=server,dir=%s,verify-peer=on", credsID, tlsCredsDir),
		)
	}
	cmd.Args = append(cmd.Args, "-incoming", "defer")

	vm.cmd = cmd
	vm.stdoutBuf.Reset()
	vm.stderrBuf.Reset()
	// The receiver is always non-interactive; capture stdout/stderr for error
	// reporting rather than binding the parent TTY.
	vm.cmd.Stdout = &vm.stdoutBuf
	vm.cmd.Stderr = &vm.stderrBuf

	vm.logger.Infof("Starting migration receiver (incoming defer, tls=%t)", tlsCredsDir != "")

	if startErr := vm.cmd.Start(); startErr != nil {
		if vm.stderrBuf.Len() > 0 {
			vm.logger.Errorf("QEMU stderr: %s", vm.stderrBuf.String())
		}
		return "", &SentinelCauseError{Sentinel: ErrQEMUFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", startErr)}}
	}

	vm.running.Store(true)
	vm.logger.Infof("Migration receiver started (PID: %d)", vm.cmd.Process.Pid)
	return credsID, nil
}
