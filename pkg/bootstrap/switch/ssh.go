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
	"bytes"
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

type sshExecutor struct {
	client *ssh.Client
}

// NewSSHExecutor creates a new SSH executor connected to the specified host.
func NewSSHExecutor(config *Config) (SSHExecutor, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}

	keyBytes, err := os.ReadFile(config.SSHKey)
	if err != nil {
		return nil, ErrSSHConnectionFailed{
			Host:  config.Host,
			Cause: fmt.Errorf("reading ssh key %s: %w", config.SSHKey, err),
		}
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, ErrSSHConnectionFailed{
			Host:  config.Host,
			Cause: fmt.Errorf("parsing ssh key: %w", err),
		}
	}

	port := config.Port
	if port == 0 {
		port = 22
	}

	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // switch mgmt uses known infra
	}

	addr := net.JoinHostPort(config.Host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, ErrSSHConnectionFailed{
			Host:  config.Host,
			Cause: err,
		}
	}

	return &sshExecutor{client: client}, nil
}

func (s *sshExecutor) Execute(ctx context.Context, command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", ErrCommandFailed{
			Command: command,
			Cause:   err,
		}
	}
	defer session.Close()

	// Handle context cancellation
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()
	defer close(done)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(command); err != nil {
		// Check if context was cancelled
		if ctx.Err() != nil {
			return "", ErrCommandFailed{
				Command: command,
				Output:  stderr.String(),
				Cause:   ctx.Err(),
			}
		}
		return "", ErrCommandFailed{
			Command: command,
			Output:  stderr.String(),
			Cause:   err,
		}
	}

	return stdout.String(), nil
}

func (s *sshExecutor) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}
