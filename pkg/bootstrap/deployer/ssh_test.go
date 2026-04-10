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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewSSHClient_InvalidKey(t *testing.T) {
	_, err := NewSSHClient("192.168.1.1", 22, "root", "/nonexistent/key")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
	var target ErrSSHKeyRead
	if !errors.As(err, &target) {
		t.Errorf("expected ErrSSHKeyRead, got %T: %v", err, err)
	}
}

func TestNewSSHClient_UnparseableKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad_key")
	if err := os.WriteFile(keyPath, []byte("not a valid ssh key"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := NewSSHClient("192.168.1.1", 22, "root", keyPath)
	if err == nil {
		t.Fatal("expected error for unparseable key")
	}
	var target ErrSSHKeyParse
	if !errors.As(err, &target) {
		t.Errorf("expected ErrSSHKeyParse, got %T: %v", err, err)
	}
}

func TestSSHClient_Connect_Unreachable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath)
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	// Use a very short timeout so the test doesn't block.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)

	err = client.Connect(ctx)
	if err == nil {
		client.Close()
		t.Fatal("expected error connecting to unreachable host")
	}
	var target ErrSSHConnect
	if !errors.As(err, &target) {
		t.Errorf("expected ErrSSHConnect, got %T: %v", err, err)
	}
}

func TestSSHClient_Run_NotConnected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath)
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	_, err = client.Run(context.Background(), "echo hello")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	var target ErrSSHNotConnected
	if !errors.As(err, &target) {
		t.Errorf("expected ErrSSHNotConnected, got %T: %v", err, err)
	}
}

func TestSSHClient_IsConnected_Default(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath)
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}
	if client.IsConnected() {
		t.Error("expected new client to not be connected")
	}
}

func TestSSHClient_Close_NotConnected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath)
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	// Close on a non-connected client should not error.
	if err := client.Close(); err != nil {
		t.Errorf("expected no error closing non-connected client, got %v", err)
	}
}

func TestSSHClient_NewShellSession_NotConnected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath)
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	_, err = client.NewShellSession(context.Background(), testLogger())
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	var target ErrSSHNotConnected
	if !errors.As(err, &target) {
		t.Errorf("expected ErrSSHNotConnected, got %T: %v", err, err)
	}
}

func TestShellSession_SendCommand(t *testing.T) {
	// Start a mock SSH server that echoes commands back with a prompt.
	listener, hostKey := startMockSSHServer(t, func(ch ssh.Channel) {
		// Simulate IOS-XE: write banner, then prompt.
		io.WriteString(ch, "Welcome to IOS-XE\r\n")
		io.WriteString(ch, "Router#\r\n")

		// Read the "terminal length 0" command.
		buf := make([]byte, 4096)
		n, _ := ch.Read(buf)
		cmd := strings.TrimSpace(string(buf[:n]))
		if strings.Contains(cmd, "terminal length 0") {
			io.WriteString(ch, cmd+"\r\n")
			io.WriteString(ch, "Router#\r\n")
		}

		// Read and echo one command, then send prompt.
		n, _ = ch.Read(buf)
		cmd = strings.TrimSpace(string(buf[:n]))
		io.WriteString(ch, cmd+"\r\n")
		io.WriteString(ch, "command output line 1\r\n")
		io.WriteString(ch, "Router#\r\n")

		// Wait for close.
		ch.Read(buf)
	})
	defer listener.Close()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	addr := listener.Addr().(*net.TCPAddr)
	client := &SSHClient{
		sshConfig: &ssh.ClientConfig{
			User:            "test",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(hostKey)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
		host: "127.0.0.1",
		port: addr.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	shell, err := client.NewShellSession(ctx, testLogger())
	if err != nil {
		t.Fatalf("NewShellSession failed: %v", err)
	}
	defer shell.Close()

	output, err := shell.SendCommand(ctx, "show version")
	if err != nil {
		t.Fatalf("SendCommand failed: %v", err)
	}

	if !strings.Contains(output, "command output line 1") {
		t.Errorf("expected 'command output line 1' in output, got: %q", output)
	}
}

func TestShellSession_Timeout(t *testing.T) {
	// Start a mock SSH server that never sends a prompt after the initial one.
	listener, hostKey := startMockSSHServer(t, func(ch ssh.Channel) {
		io.WriteString(ch, "Router#\r\n")

		// Read terminal length 0.
		buf := make([]byte, 4096)
		n, _ := ch.Read(buf)
		cmd := strings.TrimSpace(string(buf[:n]))
		if strings.Contains(cmd, "terminal length 0") {
			io.WriteString(ch, cmd+"\r\n")
			io.WriteString(ch, "Router#\r\n")
		}

		// Read the command but never respond with a prompt.
		ch.Read(buf)
		io.WriteString(ch, "partial output...\r\n")
		// Hang forever - no prompt sent.
		select {}
	})
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	client := &SSHClient{
		sshConfig: &ssh.ClientConfig{
			User:            "test",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(hostKey)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
		host: "127.0.0.1",
		port: addr.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	shell, err := client.NewShellSession(ctx, testLogger())
	if err != nil {
		t.Fatalf("NewShellSession failed: %v", err)
	}
	defer shell.Close()

	// Use a short timeout for the command.
	cmdCtx, cmdCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	t.Cleanup(cmdCancel)

	_, err = shell.SendCommand(cmdCtx, "show running-config")
	if err == nil {
		t.Fatal("expected error due to timeout")
	}

	// The error should be caused by context cancellation.
	var shellErr ErrShellCommand
	if !errors.As(err, &shellErr) {
		t.Errorf("expected ErrShellCommand, got %T: %v", err, err)
	}
}

func TestCleanLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain text",
			input:    "hello world\r\n",
			expected: "hello world",
		},
		{
			name:     "ansi escape codes",
			input:    "\x1b[32mRouter#\x1b[0m\r\n",
			expected: "Router#",
		},
		{
			name:     "no trailing newline",
			input:    "Router#",
			expected: "Router#",
		},
		{
			name:     "carriage return only",
			input:    "text\r",
			expected: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanLine(tt.input)
			if result != tt.expected {
				t.Errorf("cleanLine(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsPromptLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{name: "privileged exec", line: "Router#", expected: true},
		{name: "user exec", line: "Router>", expected: true},
		{name: "config mode", line: "Router(config)#", expected: true},
		{name: "app-hosting config", line: "Router(config-app-hosting)#", expected: true},
		{name: "interface config", line: "Router(config-if)#", expected: true},
		{name: "hostname with dots", line: "router-01.lab#", expected: true},
		{name: "empty string", line: "", expected: false},
		{name: "regular output", line: "Cisco IOS Software", expected: false},
		{name: "comment with hash", line: "! This is a comment #", expected: false},
		{name: "whitespace", line: "  ", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPromptLine(tt.line)
			if result != tt.expected {
				t.Errorf("isPromptLine(%q) = %v, want %v", tt.line, result, tt.expected)
			}
		})
	}
}

func TestStripCommandEcho(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		command  string
		expected string
	}{
		{
			name:     "normal output",
			output:   "show version\nCisco IOS XE Software\nRouter#",
			command:  "show version",
			expected: "Cisco IOS XE Software",
		},
		{
			name:     "no matching echo",
			output:   "some output\nRouter#",
			command:  "missing-command",
			expected: "some output",
		},
		{
			name:     "empty output",
			output:   "show version\nRouter#",
			command:  "show version",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripCommandEcho(tt.output, tt.command)
			if result != tt.expected {
				t.Errorf("stripCommandEcho(%q, %q) = %q, want %q",
					tt.output, tt.command, result, tt.expected)
			}
		})
	}
}

// generateTestKey generates an Ed25519 SSH private key and writes it in
// OpenSSH PEM format to the specified path.
func generateTestKey(t *testing.T, path string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyBytes := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(path, keyBytes, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}
}

// startMockSSHServer starts a minimal SSH server for testing interactive
// shell sessions. The handler receives the channel after shell is requested.
// Returns the listener and the server's host signer.
func startMockSSHServer(t *testing.T, handler func(ch ssh.Channel)) (net.Listener, ssh.Signer) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			conn.Close()
			return
		}
		defer serverConn.Close()

		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			ch, requests, err := newChan.Accept()
			if err != nil {
				continue
			}

			go func() {
				for req := range requests {
					switch req.Type {
					case "pty-req", "shell":
						req.Reply(true, nil)
					default:
						req.Reply(false, nil)
					}
				}
			}()

			handler(ch)
			ch.Close()
			return
		}
	}()

	return listener, signer
}
