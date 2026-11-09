package arp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEntriesReadErrorOnOverlongLine asserts that a line the scanner cannot
// hold surfaces as ErrReadARPTable carrying the scanner's cause, rather than
// being skipped as a malformed entry or returning a truncated table.
func TestEntriesReadErrorOnOverlongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp")
	header := "IP address       HW type     Flags       HW address            Mask     Device\n"
	valid := "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
	overlong := strings.Repeat("x", bufio.MaxScanTokenSize+1) + "\n"
	if err := os.WriteFile(path, []byte(header+valid+overlong), 0o600); err != nil {
		t.Fatalf("write table: %v", err)
	}

	entries, err := NewTable(WithPath(path)).Entries()
	if !errors.Is(err, ErrReadARPTable) {
		t.Fatalf("expected ErrReadARPTable, got %v", err)
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("expected the cause bufio.ErrTooLong to be wrapped, got %v", err)
	}
	if entries != nil {
		t.Errorf("expected no entries on a read error, got %v", entries)
	}
}

// cancelOnSendSession cancels the probe's context as soon as the probe is
// sent, so the detector's listen loop observes the cancellation before it
// reads a single packet.
type cancelOnSendSession struct {
	cancel   context.CancelFunc
	sent     int
	received int
}

func (s *cancelOnSendSession) LocalHardwareAddr() net.HardwareAddr { return localMAC }

func (s *cancelOnSendSession) SendProbe(net.IP) error {
	s.sent++
	s.cancel()
	return nil
}

func (s *cancelOnSendSession) Receive(time.Time) (*Packet, error) {
	s.received++
	return nil, ErrProbeTimeout
}

func (s *cancelOnSendSession) Close() error { return nil }

type cancelOnSendTransport struct {
	session *cancelOnSendSession
}

func (tr *cancelOnSendTransport) Open(string) (ProbeSession, error) { return tr.session, nil }

// TestDetectorCheckCancelledWhileListening asserts that a context cancelled
// after a probe is on the wire stops the detector inside its listen window:
// Check returns context.Canceled, sends no further probe and reads nothing.
func TestDetectorCheckCancelledWhileListening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &cancelOnSendSession{cancel: cancel}
	detector := NewDuplicateAddressDetector(&cancelOnSendTransport{session: session})

	if err := detector.Check(ctx, "br-int", probedIP); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if session.sent != 1 {
		t.Errorf("expected exactly one probe before cancellation, got %d", session.sent)
	}
	if session.received != 0 {
		t.Errorf("expected no receive after cancellation, got %d", session.received)
	}
}
