package harness

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// consoleReadChunk is the read size of the console reader.
const consoleReadChunk = 4096

// consoleDialInterval is how often DialConsole retries while QEMU has not
// yet created the socket.
const consoleDialInterval = 200 * time.Millisecond

// Console is an interactive session on a VM's console socket
// (qemu.Config.ConsoleSocketPath): what a person at the serial port would
// see and type. It is how a test stops U-Boot's autoboot and runs
// `tpm2 info` at its prompt.
type Console struct {
	conn net.Conn

	mu       sync.Mutex
	buf      strings.Builder // everything received so far
	readErr  error
	received chan struct{} // closed and replaced on every read
}

// DialConsole connects to the console socket, retrying until ctx ends
// because QEMU creates the socket shortly after it starts.
func DialConsole(ctx context.Context, socketPath string) (*Console, error) {
	ticker := time.NewTicker(consoleDialInterval)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		if err == nil {
			c := &Console{conn: conn, received: make(chan struct{})}
			go c.read()
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, &ConsoleError{Op: "connecting to " + socketPath, Err: err}
		case <-ticker.C:
		}
	}
}

// read drains the socket into the buffer and wakes every waiter.
func (c *Console) read() {
	chunk := make([]byte, consoleReadChunk)
	for {
		n, err := c.conn.Read(chunk)
		c.mu.Lock()
		if n > 0 {
			c.buf.Write(chunk[:n])
		}
		if err != nil {
			c.readErr = err
		}
		close(c.received)
		c.received = make(chan struct{})
		c.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// Expect waits until needle has been received since the session began
// (or since the last Discard) and returns the transcript up to and
// including it.
func (c *Console) Expect(ctx context.Context, needle string) (string, error) {
	for {
		c.mu.Lock()
		text := c.buf.String()
		readErr := c.readErr
		wait := c.received
		c.mu.Unlock()

		if i := strings.Index(text, needle); i >= 0 {
			return text[:i+len(needle)], nil
		}
		if readErr != nil {
			return text, &ConsoleError{Op: "waiting for " + needle, Err: readErr}
		}
		select {
		case <-ctx.Done():
			return text, &ConsoleTimeoutError{Needle: needle, Transcript: text}
		case <-wait:
		}
	}
}

// Send writes text to the console.
func (c *Console) Send(text string) error {
	if _, err := c.conn.Write([]byte(text)); err != nil {
		return &ConsoleError{Op: "sending " + strings.TrimSpace(text), Err: err}
	}
	return nil
}

// SendLine sends text followed by a carriage return.
func (c *Console) SendLine(text string) error {
	return c.Send(text + "\r")
}

// Discard forgets what has been received so far, so the next Expect only
// matches output produced after this point (a second prompt, not the
// first).
func (c *Console) Discard() {
	c.mu.Lock()
	c.buf.Reset()
	c.mu.Unlock()
}

// Transcript returns everything received since the session began or the
// last Discard.
func (c *Console) Transcript() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Close closes the session.
func (c *Console) Close() error {
	return c.conn.Close()
}
