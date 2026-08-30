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

package bmc

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// --- test session double ------------------------------------------------

// fakeIPMISession is an in-process ipmiSession that records every Send and
// answers from a per-(netfn,cmd) response/error table. It lets tests drive
// ipmiClient down the OEM dispatch path with no network, RMCP+ handshake,
// or TLS.
type fakeIPMISession struct {
	responses map[uint16][]byte
	errs      map[uint16]error
	// handlers answers a (netfn,cmd) from the request bytes, for commands
	// whose reply depends on the request (chunked FRU reads). Consulted
	// after errs and before responses.
	handlers map[uint16]func(data []byte) ([]byte, error)
	// activateSOL, when set, answers ActivateSOL; nil means unsupported.
	activateSOL func(instance byte) (*SOLSession, error)
	sent        []sentIPMICmd
	closed      bool
	// mu serialises Send the way rmcpSession.exchangeMu does, so the
	// fake carries the real session's one-exchange-at-a-time contract.
	mu sync.Mutex
}

type sentIPMICmd struct {
	netfn byte
	cmd   byte
	data  []byte
}

func newFakeIPMISession() *fakeIPMISession {
	return &fakeIPMISession{
		responses: make(map[uint16][]byte),
		errs:      make(map[uint16]error),
		handlers:  make(map[uint16]func(data []byte) ([]byte, error)),
	}
}

func ipmiKey(netfn, cmd byte) uint16 { return uint16(netfn)<<8 | uint16(cmd) }

func (f *fakeIPMISession) Send(netfn, cmd byte, data []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentIPMICmd{netfn: netfn, cmd: cmd, data: append([]byte(nil), data...)})
	k := ipmiKey(netfn, cmd)
	if err := f.errs[k]; err != nil {
		return nil, err
	}
	if h := f.handlers[k]; h != nil {
		return h(data)
	}
	return f.responses[k], nil
}

// serveFRU makes the fake answer Get FRU Inventory Area Info and chunked
// Read FRU Data for FRU device 0 from fru, the way a real BMC does.
func (f *fakeIPMISession) serveFRU(fru []byte) {
	f.responses[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = []byte{byte(len(fru)), byte(len(fru) >> 8), 0x00}
	f.handlers[ipmiKey(netFnStorage, cmdReadFRUData)] = func(req []byte) ([]byte, error) {
		offset := int(req[1]) | int(req[2])<<8
		count := int(req[3])
		if offset+count > len(fru) {
			count = len(fru) - offset
		}
		return append([]byte{byte(count)}, fru[offset:offset+count]...), nil
	}
}

// fruWithIdentity builds a minimal FRU image whose Board Info Area names
// boardProduct and whose Product Info Area carries productPartNumber — the
// two fields hardwareIdentity reads.
func fruWithIdentity(boardProduct, productPartNumber string) []byte {
	field := func(v string) []byte { return append([]byte{0xC0 | byte(len(v))}, v...) }
	board := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00} // version, length (patched), language, mfg date
	board = append(board, field("Supermicro")...)
	board = append(board, field(boardProduct)...)
	board = append(board, field("BSN")...)
	board = append(board, field("BPN")...)
	board = append(board, 0xC1)
	for len(board)%8 != 0 {
		board = append(board, 0x00)
	}
	board[1] = byte(len(board) / 8)

	product := []byte{0x01, 0x00, 0x00} // version, length (patched), language
	product = append(product, field("Supermicro")...)
	product = append(product, field("SuperServer")...)
	product = append(product, field(productPartNumber)...)
	product = append(product, 0xC1)
	for len(product)%8 != 0 {
		product = append(product, 0x00)
	}
	product[1] = byte(len(product) / 8)

	header := []byte{0x01, 0x00, 0x00, 0x01, byte(1 + len(board)/8), 0x00, 0x00, 0x00}
	fru := append(header, board...)
	return append(fru, product...)
}

func (f *fakeIPMISession) ActivateSOL(_ context.Context, instance byte) (*SOLSession, error) {
	if f.activateSOL != nil {
		return f.activateSOL(instance)
	}
	return nil, ErrUnsupportedOperation{Operation: "console"}
}

// fakeSOLSession builds an active SOLSession over a connection-less RMCP+
// session, the way rmcp_sol_test.go does, so Deactivate takes its
// no-connection path.
func fakeSOLSession(instance byte) *SOLSession {
	sol := &SOLSession{
		session:         &rmcpSession{logger: slog.Default()},
		logger:          slog.Default(),
		output:          make(chan []byte, 16),
		done:            make(chan struct{}),
		payloadInstance: instance,
	}
	sol.active.Store(true)
	return sol
}

func (f *fakeIPMISession) Close() error {
	f.closed = true
	return nil
}

// countSends returns how many recorded sends matched the given netfn/cmd.
func (f *fakeIPMISession) countSends(netfn, cmd byte) int {
	n := 0
	for _, s := range f.sent {
		if s.netfn == netfn && s.cmd == cmd {
			n++
		}
	}
	return n
}

// lastSend returns the most recent recorded send for the given netfn/cmd.
func (f *fakeIPMISession) lastSend(netfn, cmd byte) (sentIPMICmd, bool) {
	for i := len(f.sent) - 1; i >= 0; i-- {
		if f.sent[i].netfn == netfn && f.sent[i].cmd == cmd {
			return f.sent[i], true
		}
	}
	return sentIPMICmd{}, false
}

// deviceIDResponse builds a Get Device ID response whose 3-byte
// manufacturer IANA field (bytes 6..8) encodes iana little-endian. The
// response is padded to 12 bytes so Info()'s len>=12 gate also accepts it.
func deviceIDResponse(iana uint32) []byte {
	resp := make([]byte, 12)
	resp[6] = byte(iana)
	resp[7] = byte(iana >> 8)
	resp[8] = byte(iana >> 16)
	return resp
}

func oemTestClient(session ipmiSession) *ipmiClient {
	return &ipmiClient{
		config: &Config{
			Address:  "127.0.0.1",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolIPMI,
		},
		logger:  slog.Default(),
		session: session,
	}
}

// --- sendSmcOEMBootOverride ---------------------------------------------

func TestSendSmcOEMBootOverride(t *testing.T) {
	t.Run("PXE builds 0x30/0x70 payload and succeeds", func(t *testing.T) {
		fake := newFakeIPMISession()
		if err := sendSmcOEMBootOverride(fake, slog.Default(), BootDevicePXE, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected an OEM 0x30/0x70 send")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootPXE}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
	})

	t.Run("None maps to disable code", func(t *testing.T) {
		fake := newFakeIPMISession()
		if err := sendSmcOEMBootOverride(fake, slog.Default(), BootDeviceNone, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent, _ := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootDisable}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
	})

	t.Run("non-PXE device returns ErrBootOverrideUnsupported without a send", func(t *testing.T) {
		fake := newFakeIPMISession()
		err := sendSmcOEMBootOverride(fake, slog.Default(), BootDeviceDisk, false)
		var target ErrBootOverrideUnsupported
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootOverrideUnsupported, got %T: %v", err, err)
		}
		if len(fake.sent) != 0 {
			t.Errorf("expected no OEM send for unsupported device, got %d sends", len(fake.sent))
		}
	})

	t.Run("wire error is wrapped as ErrBootDevice", func(t *testing.T) {
		fake := newFakeIPMISession()
		wire := errors.New("completion code 0x80")
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = wire
		err := sendSmcOEMBootOverride(fake, slog.Default(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if !errors.Is(err, wire) {
			t.Errorf("expected wrapped wire error, got %v", err)
		}
	})
}

// --- manufacturerName / hardwareIdentity (IANA + FRU -> identity) -------

func TestIPMIClient_ManufacturerName(t *testing.T) {
	t.Run("Supermicro IANA maps to supermicro", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "supermicro" {
			t.Errorf("manufacturerName = %q, want %q", got, "supermicro")
		}
	})

	t.Run("unknown IANA maps to empty", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(999)
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "" {
			t.Errorf("manufacturerName = %q, want empty", got)
		}
	})

	t.Run("malformed (short) response maps to empty", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = []byte{0x01, 0x02}
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "" {
			t.Errorf("manufacturerName = %q, want empty", got)
		}
	})

	t.Run("result is cached after first resolution", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		_ = c.manufacturerName(context.Background())
		_ = c.manufacturerName(context.Background())
		if n := fake.countSends(netFnApp, cmdGetDeviceID); n != 1 {
			t.Errorf("expected Get Device ID issued once (cached), got %d", n)
		}
	})
}

func TestIPMIClient_HardwareIdentity(t *testing.T) {
	t.Run("FRU board product and part number reach the X10SDV entry without Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))
		c := oemTestClient(fake)

		id := c.hardwareIdentity(context.Background())
		if id.Manufacturer != "supermicro" || id.Model != "X10SDV-TP8F" || id.PartNumber != "SYS-5018D-FN8T-AS001" {
			t.Fatalf("identity = %+v", id)
		}
		if q := quirks.ResolveIdentity(id); q.Key != "supermicro/x10sdv" {
			t.Errorf("quirk = %q, want supermicro/x10sdv", q.Key)
		}
		if c.redfishClient != nil {
			t.Error("IPMI identity must not create a Redfish client")
		}
	})

	t.Run("part number alone names the board when the FRU board product is a placeholder", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("Super Server", "SYS-5018D-FN4T"))
		c := oemTestClient(fake)

		if q := quirks.ResolveIdentity(c.hardwareIdentity(context.Background())); q.Key != "supermicro/x10sdv" {
			t.Errorf("quirk = %q, want supermicro/x10sdv", q.Key)
		}
	})

	t.Run("a non-X10SDV Supermicro SKU resolves the manufacturer-wide entry", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("X10SLM-F", "SYS-5018D-MTF"))
		c := oemTestClient(fake)

		if q := quirks.ResolveIdentity(c.hardwareIdentity(context.Background())); q.Key != "supermicro" {
			t.Errorf("quirk = %q, want supermicro", q.Key)
		}
	})

	t.Run("undecodable FRU is a definitive vendor-only identity and is cached", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)

		id := c.hardwareIdentity(context.Background())
		if id.Manufacturer != "supermicro" || id.Model != "" || id.PartNumber != "" {
			t.Fatalf("identity = %+v, want vendor only", id)
		}
		_ = c.hardwareIdentity(context.Background())
		if n := fake.countSends(netFnStorage, cmdGetFRUInventoryArea); n != 1 {
			t.Errorf("expected the FRU probe issued once (cached), got %d", n)
		}
	})

	t.Run("FRU transient completion code (timeout) is not cached and is retried", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = ErrCompletionCode{Code: 0xC3, Command: cmdGetFRUInventoryArea, NetFn: netFnStorage}
		c := oemTestClient(fake)

		if id := c.hardwareIdentity(context.Background()); id.Manufacturer != "supermicro" {
			t.Fatalf("identity = %+v, want the vendor learned before the FRU timeout", id)
		}
		if c.identity.Load() != nil {
			t.Fatal("a BMC timeout completion code must not be cached")
		}

		delete(fake.errs, ipmiKey(netFnStorage, cmdGetFRUInventoryArea))
		fake.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))
		if id := c.hardwareIdentity(context.Background()); id.PartNumber != "SYS-5018D-FN8T-AS001" {
			t.Errorf("identity after the BMC recovered = %+v, want the FRU part number", id)
		}
	})

	t.Run("FRU 'data not present' completion code is a definitive answer and is cached", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = ErrCompletionCode{Code: 0xCB, Command: cmdGetFRUInventoryArea, NetFn: netFnStorage}
		c := oemTestClient(fake)

		_ = c.hardwareIdentity(context.Background())
		_ = c.hardwareIdentity(context.Background())
		if n := fake.countSends(netFnApp, cmdGetDeviceID); n != 1 {
			t.Errorf("expected Get Device ID issued once (cached), got %d", n)
		}
		if c.identity.Load() == nil {
			t.Error("completion code must cache the vendor-only identity")
		}
	})

	t.Run("Get Device ID transport failure is not cached and is retried", func(t *testing.T) {
		fake := newFakeIPMISession()
		wire := errors.New("timeout waiting for response")
		fake.errs[ipmiKey(netFnApp, cmdGetDeviceID)] = wire
		c := oemTestClient(fake)

		if got := c.manufacturerName(context.Background()); got != "" {
			t.Fatalf("manufacturerName during outage = %q, want empty", got)
		}
		if c.identity.Load() != nil {
			t.Fatal("transport failure must not be cached")
		}

		// The BMC comes back: the next call resolves the real vendor.
		delete(fake.errs, ipmiKey(netFnApp, cmdGetDeviceID))
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		if got := c.manufacturerName(context.Background()); got != "supermicro" {
			t.Errorf("manufacturerName after recovery = %q, want supermicro", got)
		}
		if n := fake.countSends(netFnApp, cmdGetDeviceID); n != 2 {
			t.Errorf("expected Get Device ID retried after the failure, got %d sends", n)
		}
	})

	t.Run("FRU transport failure keeps the vendor for this call but is not cached", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(netFnStorage, cmdReadFRUData)] = errors.New("timeout waiting for response")
		fake.responses[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = []byte{0x40, 0x00, 0x00}
		c := oemTestClient(fake)

		if id := c.hardwareIdentity(context.Background()); id.Manufacturer != "supermicro" {
			t.Fatalf("identity = %+v, want the vendor learned before the FRU failure", id)
		}
		if c.identity.Load() != nil {
			t.Fatal("FRU transport failure must not be cached")
		}

		delete(fake.errs, ipmiKey(netFnStorage, cmdReadFRUData))
		fake.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))
		if id := c.hardwareIdentity(context.Background()); id.PartNumber != "SYS-5018D-FN8T-AS001" {
			t.Errorf("identity after recovery = %+v, want the FRU part number", id)
		}
	})

	t.Run("concurrent first callers open one session and agree on one cached identity", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))
		// A brand-new client: the session is opened lazily by the first
		// caller through ensureOpen, which is where the shared-client
		// path (Service.clientFor) used to race.
		c := oemTestClient(nil)
		var opens atomic.Int32
		c.openSession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			opens.Add(1)
			return fake, nil
		}

		const callers = 8
		var wg sync.WaitGroup
		results := make([]quirks.Identity, callers)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = c.hardwareIdentity(context.Background())
			}(i)
		}
		wg.Wait()
		want := *c.identity.Load()
		for i, got := range results {
			if got != want {
				t.Errorf("caller %d saw %+v, want the cached %+v", i, got, want)
			}
		}
		if n := opens.Load(); n != 1 {
			t.Errorf("expected exactly one session open across concurrent first callers, got %d", n)
		}
	})

	t.Run("a caller racing with Close never opens a session after it", func(t *testing.T) {
		c := oemTestClient(nil)
		opened := false
		c.openSession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			opened = true
			return newFakeIPMISession(), nil
		}
		// Model the interleaving: the caller has passed the outer closed
		// check, then Close runs to completion, then the caller takes
		// openMu. The re-check under the lock must refuse to open.
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		c.openMu.Lock()
		closedUnderLock := c.closed.Load()
		c.openMu.Unlock()
		if !closedUnderLock {
			t.Fatal("closed must be visible under openMu after Close")
		}
		if err := c.ensureOpen(); !errors.As(err, new(ErrClientClosed)) {
			t.Fatalf("ensureOpen after Close = %v, want ErrClientClosed", err)
		}
		if err := c.ensureRedfishClient(); !errors.As(err, new(ErrClientClosed)) {
			t.Fatalf("ensureRedfishClient after Close = %v, want ErrClientClosed", err)
		}
		if opened || c.session != nil || c.redfishClient != nil {
			t.Error("no session or Redfish client may be created after Close")
		}
	})

	t.Run("Close racing with lazy open never leaves a live session or Redfish client", func(t *testing.T) {
		// Invariant: once both ensureOpen (or ensureRedfishClient) and Close
		// have returned, nothing may be left open — either the opener won
		// and Close tore it down, or Close won and the opener refused.
		// Run the pair many times under -race so both orderings occur.
		const rounds = 300
		for i := 0; i < rounds; i++ {
			c := oemTestClient(nil)
			fake := newFakeIPMISession()
			var opened atomic.Bool
			c.openSession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
				opened.Store(true)
				return fake, nil
			}

			var start, done sync.WaitGroup
			start.Add(1)
			done.Add(3)
			go func() {
				defer done.Done()
				start.Wait()
				_ = c.ensureOpen()
			}()
			go func() {
				defer done.Done()
				start.Wait()
				_ = c.ensureRedfishClient()
			}()
			go func() {
				defer done.Done()
				start.Wait()
				_ = c.Close()
			}()
			start.Done()
			done.Wait()

			c.openMu.Lock()
			session, rc := c.session, c.redfishClient
			c.openMu.Unlock()
			if session != nil || rc != nil {
				t.Fatalf("round %d: session=%v redfish=%v left open after Close", i, session != nil, rc != nil)
			}
			if opened.Load() && !fake.closed {
				t.Fatalf("round %d: session opened during the race was never closed", i)
			}
		}
	})

	t.Run("Close waits for an in-flight IPMI operation instead of pulling the session from under it", func(t *testing.T) {
		fake := newFakeIPMISession()
		c := oemTestClient(fake)
		var sawLiveSession atomic.Bool
		entered := make(chan struct{})
		fake.handlers[ipmiKey(netFnChassis, cmdChassisControl)] = func(_ []byte) ([]byte, error) {
			// Signal that the operation is inside Send, then park until
			// Close has been *requested* (it flips closed before taking
			// the lifecycle lock) and prove the session is still ours:
			// Close cannot have torn it down.
			close(entered)
			for !c.closed.Load() {
				runtime.Gosched()
			}
			sawLiveSession.Store(!fake.closed && c.session != nil)
			return nil, nil
		}

		var wg sync.WaitGroup
		wg.Add(1)
		var opErr error
		go func() {
			defer wg.Done()
			opErr = c.PowerOn(context.Background())
		}()
		<-entered
		closeErr := c.Close() // returns only after PowerOn's Send finished
		wg.Wait()

		if opErr != nil || closeErr != nil {
			t.Fatalf("PowerOn = %v, Close = %v, want both nil", opErr, closeErr)
		}
		if !sawLiveSession.Load() {
			t.Fatal("Send observed a closed or nil session while Close was pending")
		}
		if !fake.closed || c.session != nil {
			t.Error("Close must tear the session down once the operation has finished")
		}
		if err := c.PowerOn(context.Background()); !errors.As(err, new(ErrClientClosed)) {
			t.Errorf("PowerOn after Close = %v, want ErrClientClosed", err)
		}
	})

	t.Run("Close waits for an in-flight Redfish-delegated operation", func(t *testing.T) {
		c := oemTestClient(newFakeIPMISession())
		rf := &blockingRedfishClient{}
		entered := make(chan struct{})
		rf.gate = func() {
			close(entered)
			for !c.closed.Load() {
				runtime.Gosched()
			}
			rf.sawLive.Store(!rf.closed.Load() && c.redfishClient != nil)
		}
		c.redfishClient = rf

		var wg sync.WaitGroup
		wg.Add(1)
		var opErr error
		go func() {
			defer wg.Done()
			_, opErr = c.VirtualMediaStatus(context.Background())
		}()
		<-entered
		closeErr := c.Close()
		wg.Wait()

		if opErr != nil || closeErr != nil {
			t.Fatalf("VirtualMediaStatus = %v, Close = %v, want both nil", opErr, closeErr)
		}
		if !rf.sawLive.Load() {
			t.Fatal("the Redfish call observed a closed or nil client while Close was pending")
		}
		if !rf.closed.Load() || c.redfishClient != nil {
			t.Error("Close must close and drop the Redfish client once the operation has finished")
		}
		if _, err := c.VirtualMediaStatus(context.Background()); !errors.As(err, new(ErrClientClosed)) {
			t.Errorf("VirtualMediaStatus after Close = %v, want ErrClientClosed", err)
		}
	})

	t.Run("an open console pins the client: Close deactivates it before tearing the session down", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.activateSOL = func(instance byte) (*SOLSession, error) { return fakeSOLSession(instance), nil }
		c := oemTestClient(fake)

		sol, err := c.Console(context.Background())
		if err != nil {
			t.Fatalf("Console: %v", err)
		}
		if !sol.active.Load() || len(c.consoles) != 1 {
			t.Fatalf("console must be active and tracked; active=%v tracked=%d", sol.active.Load(), len(c.consoles))
		}
		// The owner never closes the console; Close must still return,
		// having deactivated it, rather than wait on the pin forever.
		if err := c.Close(); err != nil {
			t.Fatalf("Close with an open console: %v", err)
		}
		if sol.active.Load() || len(c.consoles) != 0 || c.session != nil {
			t.Errorf("after Close: active=%v tracked=%d session=%v, want deactivated, untracked, nil",
				sol.active.Load(), len(c.consoles), c.session != nil)
		}
		if err := sol.Close(); err != nil {
			t.Errorf("closing an already deactivated console = %v, want nil", err)
		}
	})

	t.Run("a console closed by its owner releases the pin exactly once", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.activateSOL = func(instance byte) (*SOLSession, error) { return fakeSOLSession(instance), nil }
		c := oemTestClient(fake)

		sol, err := c.Console(context.Background())
		if err != nil {
			t.Fatalf("Console: %v", err)
		}
		if err := sol.Close(); err != nil {
			t.Fatalf("sol.Close: %v", err)
		}
		if err := sol.Close(); err != nil {
			t.Fatalf("second sol.Close: %v", err)
		}
		if len(c.consoles) != 0 {
			t.Errorf("console still tracked after its owner closed it")
		}
		// The pin is gone: another operation and then Close both proceed.
		if _, err := c.GetBootDevice(context.Background()); err != nil {
			t.Errorf("GetBootDevice after console close: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Errorf("Close after console close: %v", err)
		}
	})

	t.Run("Close racing with a console still being activated never waits on its pin", func(t *testing.T) {
		fake := newFakeIPMISession()
		c := oemTestClient(fake)
		closeDone := make(chan error, 1)
		fake.activateSOL = func(instance byte) (*SOLSession, error) {
			// Close is requested while Console holds the pin and before
			// the console is registered; wait until Close has flipped
			// closed (it does so before its snapshot and its wait).
			go func() { closeDone <- c.Close() }()
			for !c.closed.Load() {
				runtime.Gosched()
			}
			return fakeSOLSession(instance), nil
		}

		sol, err := c.Console(context.Background())
		if !errors.As(err, new(ErrClientClosed)) || sol != nil {
			t.Fatalf("Console during Close = (%v, %v), want (nil, ErrClientClosed)", sol, err)
		}
		if err := <-closeDone; err != nil {
			t.Fatalf("Close: %v", err)
		}
		if len(c.consoles) != 0 || c.session != nil {
			t.Errorf("after Close: tracked=%d session=%v, want none", len(c.consoles), c.session != nil)
		}
	})

	t.Run("a failed console activation releases the pin", func(t *testing.T) {
		fake := newFakeIPMISession()
		c := oemTestClient(fake) // ActivateSOL unsupported → error path
		if _, err := c.Console(context.Background()); err == nil {
			t.Fatal("expected Console to fail")
		}
		if len(c.consoles) != 0 {
			t.Error("a failed activation must not be tracked")
		}
		if err := c.Close(); err != nil {
			t.Errorf("Close after failed Console: %v", err)
		}
	})

	t.Run("session open failure is ErrConnectionFailed and nothing is cached", func(t *testing.T) {
		c := oemTestClient(nil)
		c.openSession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			return nil, errors.New("rmcp+ handshake refused")
		}
		if err := c.ensureOpen(); !errors.As(err, new(ErrConnectionFailed)) {
			t.Fatalf("ensureOpen = %v, want ErrConnectionFailed", err)
		}
		if id := c.hardwareIdentity(context.Background()); id != (quirks.Identity{}) || c.identity.Load() != nil {
			t.Errorf("identity = %+v (cached=%v), want empty and uncached", id, c.identity.Load() != nil)
		}
	})

	t.Run("session unavailable returns an empty identity without caching", func(t *testing.T) {
		c := newIPMIClient(&Config{Address: "127.0.0.1", Port: 1, Username: "a", Password: "b", Protocol: ProtocolIPMI}, slog.Default())
		c.closed.Store(true)

		if id := c.hardwareIdentity(context.Background()); id != (quirks.Identity{}) {
			t.Errorf("identity = %+v, want empty", id)
		}
		if c.identity.Load() != nil {
			t.Error("unopenable session must not be cached")
		}
	})
}

// --- resolveSOLPayloadInstance -------------------------------------------

func TestIPMIClient_ResolveSOLPayloadInstance(t *testing.T) {
	t.Run("explicit config wins without any IPMI round-trip", func(t *testing.T) {
		fake := newFakeIPMISession()
		c := oemTestClient(fake)
		c.config.SOLPayloadInstance = 0x02

		if got := c.resolveSOLPayloadInstance(context.Background()); got != 0x02 {
			t.Errorf("instance = %#x, want 0x02", got)
		}
		if len(fake.sent) != 0 {
			t.Errorf("config override must not touch the BMC; %d sends", len(fake.sent))
		}
	})

	t.Run("IPMI-native identity resolves the quirk without Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))
		c := oemTestClient(fake)

		want := quirks.ResolveIdentity(quirks.Identity{Manufacturer: "supermicro", PartNumber: "SYS-5018D-FN8T-AS001"}).SOLPayloadInstance
		if got := c.resolveSOLPayloadInstance(context.Background()); got != want {
			t.Errorf("instance = %#x, want the X10SDV quirk's %#x", got, want)
		}
		if c.redfishClient != nil {
			t.Error("a board named over IPMI must not fall through to Redfish discovery")
		}
	})

	t.Run("unknown vendor over IPMI falls through to the Redfish path", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(999)
		c := oemTestClient(fake)
		c.config.Port = 1

		if got := c.resolveSOLPayloadInstance(context.Background()); got != defaultSOLPayloadInstance {
			t.Errorf("instance = %#x, want the IPMI default", got)
		}
		if c.redfishClient == nil {
			t.Error("an unidentified board must try Redfish discovery before defaulting")
		}
	})
}

// TestIPMIClient_SOLPayloadInstanceFromQuirk covers the zero-instance quirk
// (generic default) and a quirk that names an instance.
func TestIPMIClient_SOLPayloadInstanceFromQuirk(t *testing.T) {
	c := oemTestClient(newFakeIPMISession())
	if got := c.solPayloadInstanceFromQuirk(quirks.Quirk{Key: "x"}, "ipmi"); got != defaultSOLPayloadInstance {
		t.Errorf("unset instance = %#x, want default", got)
	}
	if got := c.solPayloadInstanceFromQuirk(quirks.Quirk{Key: "x", SOLPayloadInstance: 0x03}, "ipmi"); got != 0x03 {
		t.Errorf("instance = %#x, want 0x03", got)
	}
}

// blockingRedfishClient is a Client double for the IPMI client's lazy
// Redfish delegate: VirtualMediaStatus runs gate before returning, and
// Close records that it happened. Every other method is the embedded nil
// Client and must not be reached by the test.
type blockingRedfishClient struct {
	Client
	gate    func()
	closed  atomic.Bool
	sawLive atomic.Bool
}

func (b *blockingRedfishClient) VirtualMediaStatus(_ context.Context) (*VirtualMediaInfo, error) {
	b.gate()
	return &VirtualMediaInfo{}, nil
}

func (b *blockingRedfishClient) Close() error {
	b.closed.Store(true)
	return nil
}

// TestDefinitiveIPMIError pins which errors hardwareIdentity treats as the
// BMC's answer (cacheable) versus a transport failure (retry next call).
func TestDefinitiveIPMIError(t *testing.T) {
	definitive := []error{
		ErrCompletionCode{Code: 0xCB},
		ErrGetFRUInfo{Cause: ErrCompletionCode{Code: 0xC1}},
		ErrReadFRU{Offset: 0, Cause: ErrCompletionCode{Code: 0xC9}},
		ErrCompletionCode{Code: 0xCC},
		ErrCompletionCode{Code: 0xD4},
		ErrFRURead{Reason: "FRU area size is zero"},
	}
	for _, err := range definitive {
		if !definitiveIPMIError(err) {
			t.Errorf("%v must be definitive", err)
		}
	}
	transport := []error{
		errors.New("timeout"),
		ErrGetFRUInfo{Cause: errors.New("udp send failed")},
		ErrReadFRU{Offset: 16, Cause: ErrSessionClosed{}},
		ErrCompletionCode{Code: 0xC0},                       // node busy
		ErrGetFRUInfo{Cause: ErrCompletionCode{Code: 0xC3}}, // timeout
		ErrCompletionCode{Code: 0xD3},                       // destination unavailable
		ErrCompletionCode{Code: 0xFF},                       // unspecified
	}
	for _, err := range transport {
		if definitiveIPMIError(err) {
			t.Errorf("%v must be a transport failure", err)
		}
	}
}

// --- SetBootDevice OEM dispatch -----------------------------------------

func TestIPMIClient_SetBootDevice_OEMPath(t *testing.T) {
	t.Run("Supermicro PXE takes OEM path and returns nil without Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)

		if err := c.SetBootDevice(context.Background(), BootDevicePXE, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected the OEM 0x30/0x70 command to be issued")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootPXE}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
		// The OEM override is authoritative: SetBootDevice must short-circuit
		// before lazily creating a Redfish client.
		if c.redfishClient != nil {
			t.Error("expected no Redfish client to be created on the OEM success path")
		}
	})

	t.Run("OEM wire error surfaces as ErrBootDevice", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		c := oemTestClient(fake)

		err := c.SetBootDevice(context.Background(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if c.redfishClient != nil {
			t.Error("expected no Redfish client to be created on the OEM error path")
		}
	})
}

// TestIPMIClient_SetBootDevice_NoneClearsBothLayers covers the teardown
// contract measured on X10 ATEN firmware (issue #103): the OEM disable
// alone leaves a Continuous CD/virtual-media override armed, so the clear
// must issue the OEM disable AND then the Redfish PATCH None.
func TestIPMIClient_SetBootDevice_NoneClearsBothLayers(t *testing.T) {
	t.Run("Supermicro None sends OEM disable then Redfish None", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		redfish := NewMockClient()
		c.redfishClient = redfish

		if err := c.SetBootDevice(context.Background(), BootDeviceNone, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected the OEM 0x30/0x70 disable to be issued")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootDisable}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
		if n := redfish.SetBootDeviceCalls(); n != 1 {
			t.Fatalf("Redfish SetBootDevice calls = %d, want 1 (the clear must continue to Redfish)", n)
		}
		if redfish.Boot != BootDeviceNone || redfish.BootPersistent {
			t.Errorf("Redfish clear = (%q, persistent=%v), want (None, false)", redfish.Boot, redfish.BootPersistent)
		}
	})

	t.Run("OEM disable failure still clears Redfish, then reports the failure", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		c := oemTestClient(fake)
		redfish := NewMockClient()
		c.redfishClient = redfish

		err := c.SetBootDevice(context.Background(), BootDeviceNone, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if n := redfish.SetBootDeviceCalls(); n != 1 {
			t.Errorf("Redfish SetBootDevice calls = %d, want 1 (the clear still tries Redfish)", n)
		}
		if redfish.Boot != BootDeviceNone {
			t.Errorf("Redfish clear device = %q, want None", redfish.Boot)
		}
	})

	t.Run("OEM PXE failure aborts before Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		c := oemTestClient(fake)
		redfish := NewMockClient()
		c.redfishClient = redfish

		err := c.SetBootDevice(context.Background(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if n := redfish.SetBootDeviceCalls(); n != 0 {
			t.Errorf("Redfish SetBootDevice calls = %d, want 0 after an OEM wire error on a boot target", n)
		}
	})

	t.Run("Supermicro PXE still short-circuits before Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		redfish := NewMockClient()
		c.redfishClient = redfish

		if err := c.SetBootDevice(context.Background(), BootDevicePXE, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := redfish.SetBootDeviceCalls(); n != 0 {
			t.Errorf("Redfish SetBootDevice calls = %d, want 0 (PXE OEM override is authoritative)", n)
		}
	})

	t.Run("Redfish clear failure on None is an error, not best-effort", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		redfish := NewMockClient()
		redfish.SetBootDeviceErr = errors.New("redfish unavailable")
		c.redfishClient = redfish

		err := c.SetBootDevice(context.Background(), BootDeviceNone, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice when the Redfish clear fails, got %T: %v", err, err)
		}
		if n := redfish.SetBootDeviceCalls(); n != 1 {
			t.Errorf("Redfish SetBootDevice calls = %d, want 1", n)
		}
	})

	t.Run("Redfish reinforcement failure on a boot target stays best-effort", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		redfish := NewMockClient()
		redfish.SetBootDeviceErr = errors.New("redfish unavailable")
		c.redfishClient = redfish

		// CDROM is not OEM-routable, so it reaches the reinforcement.
		if err := c.SetBootDevice(context.Background(), BootDeviceCDROM, false); err != nil {
			t.Fatalf("boot-target reinforcement is best-effort; unexpected error: %v", err)
		}
		if n := redfish.SetBootDeviceCalls(); n != 1 {
			t.Errorf("Redfish SetBootDevice calls = %d, want 1", n)
		}
	})
}

// TestIPMIClient_SetBootDevice_NoneContinuesPastBootFlagsFailure verifies
// that a failed standard boot-flags command does not short-circuit the
// clear: the OEM disable and the Redfish clear still run, and the flags
// failure is reported afterwards.
func TestIPMIClient_SetBootDevice_NoneContinuesPastBootFlagsFailure(t *testing.T) {
	fake := newFakeIPMISession()
	fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
	fake.errs[ipmiKey(netFnChassis, cmdSetSystemBootOptions)] = errors.New("completion code 0xc1")
	c := oemTestClient(fake)
	redfish := NewMockClient()
	c.redfishClient = redfish

	err := c.SetBootDevice(context.Background(), BootDeviceNone, false)
	var target ErrBootDevice
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrBootDevice reporting the boot-flags failure, got %T: %v", err, err)
	}
	if _, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption); !ok {
		t.Error("expected the OEM disable to still be issued")
	}
	if n := redfish.SetBootDeviceCalls(); n != 1 || redfish.Boot != BootDeviceNone {
		t.Errorf("Redfish clear calls = %d (device %q), want 1 with None", n, redfish.Boot)
	}

	// A boot target keeps the abort-on-flags-failure behaviour.
	if err := c.SetBootDevice(context.Background(), BootDevicePXE, false); !errors.As(err, &target) {
		t.Fatalf("expected ErrBootDevice for PXE on a boot-flags failure, got %T: %v", err, err)
	}
	if n := redfish.SetBootDeviceCalls(); n != 1 {
		t.Errorf("Redfish calls after PXE abort = %d, want still 1", n)
	}
}

// TestClearBootOverrideResult pins the error precedence of the layered
// None clear.
func TestClearBootOverrideResult(t *testing.T) {
	flagsErr := errors.New("flags")
	oemErr := errors.New("oem")
	rfErr := errors.New("redfish")

	if err := clearBootOverrideResult(BootDeviceNone, nil, nil, nil); err != nil {
		t.Errorf("all layers ok: got %v, want nil", err)
	}
	if err := clearBootOverrideResult(BootDeviceNone, flagsErr, oemErr, rfErr); !errors.Is(err, rfErr) {
		t.Errorf("all failed: got %v, want the Redfish cause", err)
	}
	if err := clearBootOverrideResult(BootDeviceNone, flagsErr, oemErr, nil); !errors.Is(err, oemErr) {
		t.Errorf("flags+OEM failed: got %v, want the OEM cause", err)
	}
	if err := clearBootOverrideResult(BootDeviceNone, flagsErr, nil, nil); !errors.Is(err, flagsErr) {
		t.Errorf("flags failed: got %v, want the flags cause", err)
	}
	var target ErrBootDevice
	if err := clearBootOverrideResult(BootDeviceNone, nil, nil, rfErr); !errors.As(err, &target) || target.Device != string(BootDeviceNone) {
		t.Errorf("Redfish failed: got %T %v, want ErrBootDevice for None", err, err)
	}
}

// TestVbootSmcOEMIPMI_SessionOpener verifies the Redfish-dispatched OEM
// backend uses the injected session opener, closes the session, and maps
// an open failure to ErrBootDevice/ErrConnectionFailed.
func TestVbootSmcOEMIPMI_SessionOpener(t *testing.T) {
	t.Run("sends the OEM command over the opened session and closes it", func(t *testing.T) {
		fake := newFakeIPMISession()
		var openedPort int
		rc := &redfishClient{
			config: &Config{Address: "127.0.0.1", Port: 443, Username: "admin", Password: "secret"},
			logger: slog.Default(),
			openIPMISession: func(_ context.Context, cfg *Config, _ *slog.Logger) (ipmiSession, error) {
				openedPort = cfg.Port
				return fake, nil
			},
		}

		if err := newVbootSmcOEMIPMI(rc).SetBootDevice(context.Background(), BootDeviceNone, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if openedPort != ipmiDefaultPort {
			t.Errorf("session opened on port %d, want %d", openedPort, ipmiDefaultPort)
		}
		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected the OEM 0x30/0x70 command on the opened session")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootDisable}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
		if !fake.closed {
			t.Error("expected the short-lived session to be closed")
		}
	})

	t.Run("open failure surfaces as ErrBootDevice wrapping ErrConnectionFailed", func(t *testing.T) {
		rc := &redfishClient{
			config: &Config{Address: "127.0.0.1", Port: 443},
			logger: slog.Default(),
			openIPMISession: func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
				return nil, errors.New("rmcp: timeout")
			},
		}

		err := newVbootSmcOEMIPMI(rc).SetBootDevice(context.Background(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		var conn ErrConnectionFailed
		if !errors.As(err, &conn) {
			t.Errorf("expected ErrConnectionFailed cause, got %v", err)
		}
	})

	t.Run("unsupported device never opens a session", func(t *testing.T) {
		opened := false
		rc := &redfishClient{
			config: &Config{Address: "127.0.0.1", Port: 443},
			logger: slog.Default(),
			openIPMISession: func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
				opened = true
				return newFakeIPMISession(), nil
			},
		}

		err := newVbootSmcOEMIPMI(rc).SetBootDevice(context.Background(), BootDeviceCDROM, false)
		var unsupported ErrBootOverrideUnsupported
		if !errors.As(err, &unsupported) {
			t.Fatalf("expected ErrBootOverrideUnsupported, got %T: %v", err, err)
		}
		if opened {
			t.Error("expected no RMCP+ session for a device the OEM command cannot route")
		}
	})
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
