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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// TestRedfishClient_HardwareIdentity_IsTheQuirkSource asserts the exported
// identity is the same value resolveQuirk matches on, so an out-of-process
// caller lands on the client's own registry entry. The fixture is the mini
// fleet's ATEN firmware: a placeholder Model, board named only by
// PartNumber, which resolves the board entry rather than the
// manufacturer-wide one.
func TestRedfishClient_HardwareIdentity_IsTheQuirkSource(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)
	state.manufacturer = "Supermicro"
	state.model = "Super Server"
	state.partNumber = "SYS-5018D-FN8T-AS001"

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	// Called before any explicit discovery: the method must force it,
	// because the identifiers are only cached once the system resource
	// has been read.
	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}

	want := quirks.Identity{Manufacturer: "Supermicro", Model: "Super Server", PartNumber: "SYS-5018D-FN8T-AS001"}
	if id != want {
		t.Errorf("identity = %+v, want %+v", id, want)
	}
	if got, want := quirks.ResolveIdentity(id).Key, client.resolveQuirk().Key; got != want {
		t.Errorf("caller resolves %q, client resolves %q", got, want)
	}
	if got := quirks.ResolveIdentity(id).Key; got != "supermicro/x10sdv" {
		t.Errorf("quirk = %q, want supermicro/x10sdv", got)
	}
}

// TestRedfishClient_HardwareIdentity_UnreachableIsAnError verifies an
// unreadable controller reports an error rather than a zero identity a
// caller would mistake for "unidentified hardware".
func TestRedfishClient_HardwareIdentity_UnreachableIsAnError(t *testing.T) {
	server, _ := mockRedfishServer(t)
	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })
	server.Close()

	id, err := client.HardwareIdentity(context.Background())
	if err == nil {
		t.Fatalf("HardwareIdentity on a closed server returned %+v, want an error", id)
	}
	if id != (quirks.Identity{}) {
		t.Errorf("identity on failure = %+v, want zero", id)
	}
}

// newIdentityIPMIClient builds an ipmiClient over a fake session that
// answers Get Device ID with the Supermicro IANA number and serves a FRU
// naming boardProduct and productPartNumber.
func newIdentityIPMIClient(boardProduct, productPartNumber string) (*ipmiClient, *fakeIPMISession) {
	session := newFakeIPMISession()
	session.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
	session.serveFRU(fruWithIdentity(boardProduct, productPartNumber))
	return oemTestClient(session), session
}

// TestIPMIClient_HardwareIdentity_IsTheQuirkSource asserts the exported
// identity over IPMI is the vendor name plus the FRU Board Product and
// Product Part Number — the fields the client's own quirk resolution uses.
func TestIPMIClient_HardwareIdentity_IsTheQuirkSource(t *testing.T) {
	client, _ := newIdentityIPMIClient("X10SDV-TP8F", "SYS-5018D-FN8T-AS001")

	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}

	want := quirks.Identity{Manufacturer: vendorKeySupermicro, Model: "X10SDV-TP8F", PartNumber: "SYS-5018D-FN8T-AS001"}
	if id != want {
		t.Errorf("identity = %+v, want %+v", id, want)
	}
	if got, want := quirks.ResolveIdentity(id).Key, quirks.ResolveIdentity(client.hardwareIdentity(context.Background())).Key; got != want {
		t.Errorf("caller resolves %q, client resolves %q", got, want)
	}
	if got := quirks.ResolveIdentity(id).Key; got != "supermicro/x10sdv" {
		t.Errorf("quirk = %q, want supermicro/x10sdv", got)
	}
}

// TestIPMIClient_HardwareIdentity_DivergesFromSystemInfo is why this method
// exists at all rather than a PartNumber bolted onto SystemInfo. The two
// surfaces read different FRU fields: SystemInfo.Product is the Product
// Info Area's Product Name, the quirk identity's Model is the Board Info
// Area's Board Product. On a board whose part number is blank — Supermicro
// firmware that fills only the board area — an identity rebuilt from
// SystemInfo resolves the manufacturer-wide entry while the client itself
// uses the board entry. Adding PartNumber to SystemInfo would not close
// that gap; this test fails if anyone tries.
func TestIPMIClient_HardwareIdentity_DivergesFromSystemInfo(t *testing.T) {
	client, _ := newIdentityIPMIClient("X10SDV-TP8F", "")

	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}
	info, err := client.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}

	fromIdentity := quirks.ResolveIdentity(id).Key
	fromSystemInfo := quirks.ResolveIdentity(quirks.Identity{
		Manufacturer: info.Manufacturer,
		Model:        info.Product,
	}).Key

	if fromIdentity != "supermicro/x10sdv" {
		t.Errorf("identity resolved %q, want supermicro/x10sdv", fromIdentity)
	}
	if fromSystemInfo == fromIdentity {
		t.Fatalf("SystemInfo now resolves the same entry (%q) as the client's identity — "+
			"if that is intentional, HardwareIdentity's reason for existing has changed and "+
			"docs/architecture/vendor-quirks.md needs revisiting", fromSystemInfo)
	}
	if info.Product == id.Model {
		t.Errorf("SystemInfo.Product = %q equals identity Model; the fixture no longer "+
			"exercises the Product Name vs Board Product split", info.Product)
	}
}

// TestIPMIClient_HardwareIdentity_TransportFailureIsNotCached verifies a
// BMC that could not be reached reports an error and leaves the cache
// empty, so a later call retries rather than serving a half-read identity
// for the client's lifetime.
func TestIPMIClient_HardwareIdentity_TransportFailureIsNotCached(t *testing.T) {
	session := newFakeIPMISession()
	session.errs[ipmiKey(netFnApp, cmdGetDeviceID)] = ErrCompletionCode{Code: 0xC0} // node busy: retryable
	client := oemTestClient(session)

	if _, err := client.HardwareIdentity(context.Background()); err == nil {
		t.Fatal("HardwareIdentity on a busy BMC returned no error")
	}
	if client.identity.Load() != nil {
		t.Error("a retryable transport failure was cached")
	}

	// The BMC recovers; the retry must see the real identity.
	delete(session.errs, ipmiKey(netFnApp, cmdGetDeviceID))
	session.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
	session.serveFRU(fruWithIdentity("X10SDV-TP8F", "SYS-5018D-FN8T-AS001"))

	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity after recovery: %v", err)
	}
	if got := quirks.ResolveIdentity(id).Key; got != "supermicro/x10sdv" {
		t.Errorf("quirk after recovery = %q, want supermicro/x10sdv", got)
	}
}

// TestMockClient_HardwareIdentity keeps the test double honest: it must
// serve the identity independently of System, because the real clients
// derive the two from different fields.
func TestMockClient_HardwareIdentity(t *testing.T) {
	m := NewMockClient()
	m.System = &SystemInfo{Manufacturer: "Dell Inc.", Product: "PowerEdge R640"}
	m.Identity = quirks.Identity{Manufacturer: "Supermicro", Model: "Super Server", PartNumber: "SYS-5018D-FN8T-AS001"}

	id, err := m.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}
	if id != m.Identity {
		t.Errorf("identity = %+v, want %+v", id, m.Identity)
	}
	if m.HardwareIdentityCalls() != 1 {
		t.Errorf("HardwareIdentityCalls = %d, want 1", m.HardwareIdentityCalls())
	}
}

// TestIPMIClient_HardwareIdentity_PinsTheSessionAgainstClose verifies the
// exported entry point takes the lifecycle pin. The internal callers hold
// one already; an out-of-process caller has no way to, so without the pin a
// concurrent Close could nil the session between the ensureOpen inside
// resolveHardwareIdentity and the FRU round-trips that follow. A closed
// client must report ErrClientClosed, not touch the torn-down session.
func TestIPMIClient_HardwareIdentity_PinsTheSessionAgainstClose(t *testing.T) {
	client, session := newIdentityIPMIClient("X10SDV-TP8F", "SYS-5018D-FN8T-AS001")
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := client.HardwareIdentity(context.Background())
	var closed ErrClientClosed
	if !errors.As(err, &closed) {
		t.Fatalf("HardwareIdentity on a closed client = %v, want ErrClientClosed", err)
	}
	if n := session.countSends(netFnApp, cmdGetDeviceID); n != 0 {
		t.Errorf("closed client still sent %d Get Device ID commands", n)
	}
}

// TestIPMIClient_HardwareIdentity_PartialSurvivesFRUFailure pins the
// contract the bootstrap side depends on: when the FRU read fails
// retryably, the vendor learned from Get Device ID comes back ALONGSIDE the
// error, and the client's own quirk resolution uses it. A caller that
// treated the error as "nothing learned" would put the installer on
// Default() while this client is on the vendor entry.
func TestIPMIClient_HardwareIdentity_PartialSurvivesFRUFailure(t *testing.T) {
	session := newFakeIPMISession()
	session.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
	session.errs[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = ErrCompletionCode{
		Code: 0xC3, Command: cmdGetFRUInventoryArea, NetFn: netFnStorage, // timeout: retryable
	}
	client := oemTestClient(session)

	id, err := client.HardwareIdentity(context.Background())
	if err == nil {
		t.Fatal("HardwareIdentity returned no error for a retryable FRU failure")
	}
	if id.Manufacturer != vendorKeySupermicro {
		t.Fatalf("partial identity = %+v, want the vendor learned before the FRU timeout", id)
	}
	if got := quirks.ResolveIdentity(id).Key; got != vendorKeySupermicro {
		t.Errorf("partial identity resolves %q, want %q", got, vendorKeySupermicro)
	}
	// And that is the entry this very client uses for its own decisions.
	if got := quirks.ResolveIdentity(client.hardwareIdentity(context.Background())).Key; got != vendorKeySupermicro {
		t.Errorf("client's own quirk = %q, want %q", got, vendorKeySupermicro)
	}
}

// TestRedfishClient_HardwareIdentity_RetriesAfterTransientDiscoveryFailure
// covers a retry that could never work. Discovery gates every Redfish
// operation, so caching a FAILED discovery would make one service-root blip
// permanently fatal for the client — and it would silently defeat the
// bootstrap layer, which re-reads a failed HardwareIdentity precisely because
// a retryable failure may succeed a moment later. Against a cached error that
// retry is a no-op, and the installer config is written with no hardware keys
// while a later fresh client resolves the board entry.
func TestRedfishClient_HardwareIdentity_RetriesAfterTransientDiscoveryFailure(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)
	state.manufacturer = "Supermicro"
	state.model = "Super Server"
	state.partNumber = "SYS-5018D-FN8T-AS001"

	// Fail the service root once, then let the real mux answer.
	var rootHits int32
	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/" || r.URL.Path == "/redfish/v1" {
			if atomic.AddInt32(&rootHits, 1) == 1 {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	if _, err := client.HardwareIdentity(context.Background()); err == nil {
		t.Fatal("first read should surface the transient discovery failure")
	}

	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("retry after a transient failure: %v — a cached discovery error makes the caller's retry a no-op", err)
	}
	if got := quirks.ResolveIdentity(id).Key; got != "supermicro/x10sdv" {
		t.Errorf("quirk after recovery = %q, want supermicro/x10sdv", got)
	}
}

// TestRedfishClient_Discovery_LatchesOnlyOnSuccess pins the caching rule
// directly: a successful discovery is performed once and reused, so the fix
// above does not turn every call into a fresh round-trip.
func TestRedfishClient_Discovery_LatchesOnlyOnSuccess(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)
	state.manufacturer = "Supermicro"

	var rootHits int32
	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/" || r.URL.Path == "/redfish/v1" {
			atomic.AddInt32(&rootHits, 1)
		}
		inner.ServeHTTP(w, r)
	})

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	for i := 0; i < 3; i++ {
		if _, err := client.HardwareIdentity(context.Background()); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&rootHits); got != 1 {
		t.Errorf("service root fetched %d times across 3 reads, want 1 — success must latch", got)
	}
}

// TestRedfishClient_Discovery_NegativeCacheBoundsPollingCost pins the cost
// bound. Discovery gates eight operations, several called from polling loops
// — waitForPowerOff polls PowerStatus 20 times at 5s intervals — so retrying
// discovery on every call would make each iteration pay a full discovery
// timeout against a wedged BMC, turning one wait into minutes. Repeated
// gated calls inside the TTL must reuse the failure instead of re-dialling.
func TestRedfishClient_Discovery_NegativeCacheBoundsPollingCost(t *testing.T) {
	var rootHits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rootHits, 1)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	// Stand in for a polling loop: several gated calls in quick succession.
	for i := 0; i < 5; i++ {
		if _, err := client.PowerStatus(context.Background()); err == nil {
			t.Fatalf("call %d unexpectedly succeeded against a failing BMC", i)
		}
	}
	if got := atomic.LoadInt32(&rootHits); got != 1 {
		t.Errorf("service root attempted %d times across 5 polls, want 1 — "+
			"each extra attempt costs a full discovery timeout in a 20-iteration loop", got)
	}
}

// TestRedfishClient_HardwareIdentity_BypassesTheNegativeCache is the other
// half of the bound: the identity read is retried deliberately by the
// bootstrap layer and is not in a polling loop, so it must NOT be served the
// negative cache — otherwise that retry is as inert as sync.Once made it.
func TestRedfishClient_HardwareIdentity_BypassesTheNegativeCache(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)
	state.manufacturer = "Supermicro"
	state.model = "Super Server"
	state.partNumber = "SYS-5018D-FN8T-AS001"

	var rootHits int32
	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/" || r.URL.Path == "/redfish/v1" {
			if atomic.AddInt32(&rootHits, 1) == 1 {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	if _, err := client.HardwareIdentity(context.Background()); err == nil {
		t.Fatal("first identity read should surface the transient failure")
	}
	// Immediately, well inside discoveryFailureTTL.
	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("identity retry was served the negative cache: %v", err)
	}
	if got := quirks.ResolveIdentity(id).Key; got != "supermicro/x10sdv" {
		t.Errorf("quirk after recovery = %q, want supermicro/x10sdv", got)
	}
}
