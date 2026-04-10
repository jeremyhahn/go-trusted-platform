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
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// promptPattern matches IOS-XE prompts such as "Router#", "Router(config)#",
// "Router(config-app-hosting)#", or "Router>".
var promptPattern = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+(?:\([A-Za-z0-9._/-]+\))?[#>]\s*$`)

// ansiEscape matches ANSI escape sequences for terminal control codes.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// SSHClient wraps golang.org/x/crypto/ssh for deployer operations.
type SSHClient struct {
	sshConfig *ssh.ClientConfig
	host      string
	port      int
	client    *ssh.Client
	connected atomic.Bool
}

// NewSSHClient creates a new SSH client from the given parameters.
func NewSSHClient(host string, port int, user, keyPath string) (*SSHClient, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, ErrSSHKeyRead{Path: keyPath, Cause: err}
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, ErrSSHKeyParse{Path: keyPath, Cause: err}
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return &SSHClient{
		sshConfig: sshConfig,
		host:      host,
		port:      port,
	}, nil
}

// Connect establishes the SSH connection with context-based cancellation.
func (c *SSHClient) Connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.host, strconv.Itoa(c.port))

	// Use a dialer with context for cancellation support.
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ErrSSHConnect{Host: c.host, Port: c.port, Cause: err}
	}

	// Perform SSH handshake over the raw connection.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, c.sshConfig)
	if err != nil {
		conn.Close()
		return ErrSSHConnect{Host: c.host, Port: c.port, Cause: err}
	}

	c.client = ssh.NewClient(sshConn, chans, reqs)
	c.connected.Store(true)
	return nil
}

// Run executes a command on the remote host and returns the combined output.
func (c *SSHClient) Run(ctx context.Context, command string) (string, error) {
	if !c.connected.Load() {
		return "", ErrSSHNotConnected{Host: c.host, Port: c.port}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", ErrSSHCommand{Command: command, Cause: err}
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run with context cancellation via a done channel.
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case err := <-done:
		if err != nil {
			output := stderr.String()
			if output == "" {
				output = stdout.String()
			}
			return output, ErrSSHCommand{Command: command, Output: output, Cause: err}
		}
		return stdout.String(), nil
	case <-ctx.Done():
		session.Signal(ssh.SIGTERM)
		return "", ErrSSHCommand{Command: command, Cause: ctx.Err()}
	}
}

// CopyFile copies a local file to a remote path using SSH cat with base64 encoding.
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

	_, err = c.Run(ctx, cmd)
	if err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}
	return nil
}

// CopyFileStream streams a local file to a remote path via the SSH session's
// stdin pipe ("cat > remotePath"). Unlike CopyFile, it does not buffer the
// whole file in memory and has no argv length limit, so it's the right tool
// for ISO-sized payloads (hundreds of MB to multiple GB).
//
// Atomicity is provided by writing to "<remotePath>.partial" first and then
// renaming to remotePath in a single SSH command. The rename is atomic on
// the same filesystem.
//
// Idempotency is up to the caller — this method always uploads. The
// orchestrator's ISO stager compares size+mtime first and skips this call on
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

	session, err := c.client.NewSession()
	if err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}

	partial := remotePath + ".partial"
	// `cat > .partial && mv .partial final` — single shell invocation, atomic
	// rename on the remote side. Quote the paths to survive spaces.
	remoteCmd := "cat > '" + partial + "' && mv '" + partial + "' '" + remotePath + "'"

	if err := session.Start(remoteCmd); err != nil {
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}

	// Stream the file to stdin in a goroutine; return errors via channel so
	// we can also watch ctx.Done() without blocking on io.Copy.
	copyErrCh := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(stdin, src)
		closeErr := stdin.Close()
		if copyErr != nil {
			copyErrCh <- copyErr
			return
		}
		copyErrCh <- closeErr
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		<-copyErrCh
		return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: ctx.Err()}
	case copyErr := <-copyErrCh:
		if copyErr != nil {
			return ErrFileCopy{Local: localPath, Remote: remotePath, Cause: copyErr}
		}
	}

	if err := session.Wait(); err != nil {
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

// Close closes the SSH connection.
func (c *SSHClient) Close() error {
	if c.client != nil && c.connected.Load() {
		c.connected.Store(false)
		return c.client.Close()
	}
	return nil
}

// IsConnected returns whether the SSH client is connected.
func (c *SSHClient) IsConnected() bool {
	return c.connected.Load()
}

// ShellSession wraps an SSH shell session for interactive command execution.
// Required for IOS-XE devices where exec mode drops the connection after
// each command.
type ShellSession struct {
	session *ssh.Session
	stdin   io.Writer
	reader  *bufio.Reader
	logger  *slog.Logger
}

// NewShellSession opens an interactive shell on the SSH client. It requests
// a VT100 pseudo-terminal and starts a shell, then reads the initial
// banner and prompt before returning.
func (c *SSHClient) NewShellSession(ctx context.Context, logger *slog.Logger) (*ShellSession, error) {
	if !c.connected.Load() {
		return nil, ErrSSHNotConnected{Host: c.host, Port: c.port}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return nil, ErrShellSession{Phase: "create-session", Cause: err}
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, ErrShellSession{Phase: "stdin-pipe", Cause: err}
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, ErrShellSession{Phase: "stdout-pipe", Cause: err}
	}

	// Request a PTY for interactive shell. IOS-XE requires this.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := session.RequestPty("vt100", 40, 200, modes); err != nil {
		session.Close()
		return nil, ErrShellSession{Phase: "request-pty", Cause: err}
	}

	if err := session.Shell(); err != nil {
		session.Close()
		return nil, ErrShellSession{Phase: "start-shell", Cause: err}
	}

	s := &ShellSession{
		session: session,
		stdin:   stdinPipe,
		reader:  bufio.NewReaderSize(stdoutPipe, 65536),
		logger:  logger,
	}

	// Read the initial banner and prompt.
	if _, err := s.readUntilPrompt(ctx); err != nil {
		session.Close()
		return nil, ErrShellSession{Phase: "read-banner", Cause: err}
	}

	// Disable terminal paging so output is not blocked by --More-- prompts.
	if _, err := s.SendCommand(ctx, "terminal length 0"); err != nil {
		logger.Warn("failed to set terminal length 0, paged output may block",
			slog.String("error", err.Error()))
	}

	return s, nil
}

// SendCommand sends a command string to the interactive shell and waits for
// the next prompt to appear. It returns the output between the command echo
// and the prompt.
func (s *ShellSession) SendCommand(ctx context.Context, command string) (string, error) {
	s.logger.Debug("shell: sending command", slog.String("cmd", command))

	if _, err := io.WriteString(s.stdin, command+"\n"); err != nil {
		return "", ErrShellCommand{Command: command, Cause: err}
	}

	output, err := s.readUntilPrompt(ctx)
	if err != nil {
		return output, ErrShellCommand{Command: command, Cause: err}
	}

	// Strip the echoed command from the beginning of the output.
	cleaned := stripCommandEcho(output, command)
	s.logger.Debug("shell: response received",
		slog.String("cmd", command),
		slog.Int("bytes", len(cleaned)))

	return cleaned, nil
}

// SendCommandExpect sends a command and waits for a specific substring in the
// output instead of a prompt. This is useful for commands like "copy" that
// present intermediate prompts (e.g., "Destination filename").
func (s *ShellSession) SendCommandExpect(ctx context.Context, command, expect string) (string, error) {
	s.logger.Debug("shell: sending command with expected output",
		slog.String("cmd", command),
		slog.String("expect", expect))

	if _, err := io.WriteString(s.stdin, command+"\n"); err != nil {
		return "", ErrShellCommand{Command: command, Cause: err}
	}

	output, err := s.readUntilString(ctx, expect)
	if err != nil {
		return output, ErrShellCommand{Command: command, Cause: err}
	}

	return output, nil
}

// SendLine sends a raw line (e.g., an empty line to confirm a prompt) without
// expecting a specific prompt pattern afterward. It reads until the next
// prompt appears.
func (s *ShellSession) SendLine(ctx context.Context, line string) (string, error) {
	if _, err := io.WriteString(s.stdin, line+"\n"); err != nil {
		return "", ErrShellCommand{Command: line, Cause: err}
	}
	return s.readUntilPrompt(ctx)
}

// Close closes the shell session.
func (s *ShellSession) Close() error {
	return s.session.Close()
}

// readUntilPrompt reads output from the shell until a line matching the IOS-XE
// prompt pattern is detected, or the context is cancelled.
func (s *ShellSession) readUntilPrompt(ctx context.Context) (string, error) {
	var buf strings.Builder
	lineCh := make(chan readResult, 1)

	for {
		go func() {
			line, err := s.reader.ReadString('\n')
			lineCh <- readResult{line: line, err: err}
		}()

		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		case result := <-lineCh:
			if result.err != nil {
				// If we got partial data with EOF, check if it contains a prompt.
				if result.line != "" {
					cleaned := cleanLine(result.line)
					buf.WriteString(cleaned)
					if isPromptLine(cleaned) {
						return buf.String(), nil
					}
				}
				return buf.String(), ErrShellRead{Cause: result.err}
			}

			cleaned := cleanLine(result.line)
			buf.WriteString(cleaned)
			buf.WriteByte('\n')

			if isPromptLine(cleaned) {
				return buf.String(), nil
			}
		}
	}
}

// readUntilString reads output until the specified substring is found.
func (s *ShellSession) readUntilString(ctx context.Context, substr string) (string, error) {
	var buf strings.Builder
	lineCh := make(chan readResult, 1)

	for {
		go func() {
			line, err := s.reader.ReadString('\n')
			lineCh <- readResult{line: line, err: err}
		}()

		select {
		case <-ctx.Done():
			return buf.String(), ctx.Err()
		case result := <-lineCh:
			if result.err != nil {
				if result.line != "" {
					cleaned := cleanLine(result.line)
					buf.WriteString(cleaned)
					if strings.Contains(cleaned, substr) {
						return buf.String(), nil
					}
				}
				return buf.String(), ErrShellRead{Cause: result.err}
			}

			cleaned := cleanLine(result.line)
			buf.WriteString(cleaned)
			buf.WriteByte('\n')

			if strings.Contains(cleaned, substr) {
				return buf.String(), nil
			}
		}
	}
}

// readResult carries the result of a single line read from the shell.
type readResult struct {
	line string
	err  error
}

// cleanLine strips ANSI escape sequences and trailing carriage returns.
func cleanLine(line string) string {
	line = ansiEscape.ReplaceAllString(line, "")
	line = strings.TrimRight(line, "\r\n")
	return line
}

// isPromptLine returns true if the line matches an IOS-XE prompt pattern.
func isPromptLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return promptPattern.MatchString(trimmed)
}

// stripCommandEcho removes the echoed command from the beginning of shell
// output and trims the trailing prompt line.
func stripCommandEcho(output, command string) string {
	lines := strings.Split(output, "\n")
	start := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, strings.TrimSpace(command)) {
			start = i + 1
			break
		}
	}

	// Remove the trailing prompt line.
	end := len(lines)
	for end > start {
		trimmed := strings.TrimSpace(lines[end-1])
		if trimmed == "" || isPromptLine(trimmed) {
			end--
		} else {
			break
		}
	}

	if start >= end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}
