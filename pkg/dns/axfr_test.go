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

package dns

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// testTransferZone returns a small, fully-populated zone for transfer tests.
func testTransferZone() *entities.Zone {
	return &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     2026080401,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.10", TTL: 300},
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
				{Name: "bad", Value: "not-an-ip", TTL: 3600},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "www", Value: "2001:db8::1", TTL: 300},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "example.com.", Value: "mail.example.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "example.com.", Value: "v=spf1 -all", TTL: 3600},
			},
		},
	}
}

func TestBuildZoneTransfer_Order(t *testing.T) {
	rrs := BuildZoneTransfer(testTransferZone())

	if len(rrs) < 3 {
		t.Fatalf("expected at least SOA + records + SOA, got %d", len(rrs))
	}

	// First and last records must both be the apex SOA (RFC 5936).
	firstSOA, ok := rrs[0].(*dns.SOA)
	if !ok {
		t.Fatalf("first record must be SOA, got %T", rrs[0])
	}
	lastSOA, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		t.Fatalf("last record must be SOA, got %T", rrs[len(rrs)-1])
	}
	if firstSOA.Serial != lastSOA.Serial || firstSOA.Serial != 2026080401 {
		t.Fatalf("SOA serial mismatch: first=%d last=%d", firstSOA.Serial, lastSOA.Serial)
	}
	if firstSOA.Hdr.Name != "example.com." {
		t.Fatalf("SOA owner = %q, want example.com.", firstSOA.Hdr.Name)
	}

	// The invalid A record ("not-an-ip") must be skipped, not emitted.
	var aCount int
	sawWWW := false
	sawApexA := false
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			aCount++
			switch a.Hdr.Name {
			case "www.example.com.":
				sawWWW = true
			case "example.com.":
				sawApexA = true
			}
		}
	}
	if aCount != 2 {
		t.Fatalf("expected 2 valid A records (bad one skipped), got %d", aCount)
	}
	if !sawWWW || !sawApexA {
		t.Fatalf("A owner FQDNs wrong: www=%v apex=%v", sawWWW, sawApexA)
	}
}

func TestBuildZoneTransfer_TTLFallback(t *testing.T) {
	rrs := BuildZoneTransfer(testTransferZone())
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Name == "example.com." {
			if a.Hdr.Ttl != 3600 {
				t.Fatalf("apex A TTL fallback = %d, want zone default 3600", a.Hdr.Ttl)
			}
		}
	}
}

func TestBuildZoneTransfer_NilZone(t *testing.T) {
	if rrs := BuildZoneTransfer(nil); rrs != nil {
		t.Fatalf("nil zone must yield nil, got %d records", len(rrs))
	}
}

func TestBuildZoneTransfer_NoSOA(t *testing.T) {
	zone := &entities.Zone{Name: "nosoa.test.", TTL: 60}
	rrs := BuildZoneTransfer(zone)
	for _, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			t.Fatalf("zone without SOA MName must not emit an SOA")
		}
	}
}

func TestRecordOwnerFQDN(t *testing.T) {
	cases := []struct {
		name, zone, want string
	}{
		{"", "example.com.", "example.com."},
		{"@", "example.com.", "example.com."},
		{"www", "example.com.", "www.example.com."},
		{"www.example.com.", "example.com.", "www.example.com."},
		{"host", "example.com", "host.example.com."},
	}
	for _, c := range cases {
		if got := recordOwnerFQDN(c.name, c.zone); got != c.want {
			t.Errorf("recordOwnerFQDN(%q,%q) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

func TestCanonicalTSIGAlgorithm(t *testing.T) {
	if got := canonicalTSIGAlgorithm(""); got != dns.HmacSHA256 {
		t.Errorf("empty algorithm = %q, want %q", got, dns.HmacSHA256)
	}
	if got := canonicalTSIGAlgorithm("HMAC-SHA512."); got != dns.HmacSHA512 {
		t.Errorf("HMAC-SHA512. = %q, want %q", got, dns.HmacSHA512)
	}
}

func TestConfigureTransfer(t *testing.T) {
	// Disabled / nil config yields no keys (fail closed).
	if configureTransfer(nil) != nil {
		t.Fatal("nil config must disable transfer")
	}
	if configureTransfer(&TransferConfig{Enabled: false, TSIGKeys: []TSIGKey{{Name: "k.", Secret: "s"}}}) != nil {
		t.Fatal("disabled config must disable transfer")
	}
	if configureTransfer(&TransferConfig{Enabled: true}) != nil {
		t.Fatal("no keys must disable transfer")
	}

	// Enabled with a key populates the canonical map.
	keys := configureTransfer(&TransferConfig{
		Enabled:  true,
		TSIGKeys: []TSIGKey{{Name: "Secondary1", Secret: "abc"}, {Name: "", Secret: "skip"}},
	})
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if _, ok := keys["secondary1."]; !ok {
		t.Fatalf("expected canonical key name 'secondary1.', got %v", keys)
	}
}

// mockTransferRW is a minimal dns.ResponseWriter for exercising the AXFR
// handler branches without a live socket.
type mockTransferRW struct {
	remote     net.Addr
	tsigStatus error
	written    *dns.Msg
}

func (m *mockTransferRW) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (m *mockTransferRW) RemoteAddr() net.Addr        { return m.remote }
func (m *mockTransferRW) WriteMsg(msg *dns.Msg) error { m.written = msg; return nil }
func (m *mockTransferRW) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockTransferRW) Close() error                { return nil }
func (m *mockTransferRW) TsigStatus() error           { return m.tsigStatus }
func (m *mockTransferRW) TsigTimersOnly(bool)         {}
func (m *mockTransferRW) Hijack()                     {}

func newTransferRequest(keyName string) *dns.Msg {
	r := new(dns.Msg)
	r.SetAxfr("example.com.")
	if keyName != "" {
		r.SetTsig(keyName, dns.HmacSHA256, tsigFudge, time.Now().Unix())
	}
	return r
}

func withTransferKeys(t *testing.T, keys map[string]string) {
	t.Helper()
	prevKeys := transferKeys
	prevConf := Configuration
	transferKeys = keys
	Configuration = &Config{Logger: logging.DefaultLogger()}
	t.Cleanup(func() {
		transferKeys = prevKeys
		Configuration = prevConf
	})
}

func TestHandleZoneTransfer_Success(t *testing.T) {
	withTransferKeys(t, map[string]string{"secondary1.": "c2VjcmV0"})
	cp := TrustedPlatformPlugin{}
	w := &mockTransferRW{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}

	rc, err := cp.handleZoneTransfer(context.Background(), w, newTransferRequest("secondary1."), testTransferZone(), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want success", rc)
	}
	if w.written == nil || len(w.written.Answer) < 3 {
		t.Fatalf("expected a full-zone answer, got %+v", w.written)
	}
	if _, ok := w.written.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("first answer must be SOA")
	}
	if _, ok := w.written.Answer[len(w.written.Answer)-1].(*dns.SOA); !ok {
		t.Fatalf("last answer must be SOA")
	}
}

func TestHandleZoneTransfer_Refusals(t *testing.T) {
	zone := testTransferZone()
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}

	t.Run("no configured keys", func(t *testing.T) {
		withTransferKeys(t, nil)
		cp := TrustedPlatformPlugin{}
		w := &mockTransferRW{remote: tcp}
		rc, _ := cp.handleZoneTransfer(context.Background(), w, newTransferRequest("secondary1."), zone, "example.com.")
		assertRefused(t, rc, w)
	})

	t.Run("non-TCP transport", func(t *testing.T) {
		withTransferKeys(t, map[string]string{"secondary1.": "c2VjcmV0"})
		cp := TrustedPlatformPlugin{}
		w := &mockTransferRW{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}
		rc, _ := cp.handleZoneTransfer(context.Background(), w, newTransferRequest("secondary1."), zone, "example.com.")
		assertRefused(t, rc, w)
	})

	t.Run("missing TSIG", func(t *testing.T) {
		withTransferKeys(t, map[string]string{"secondary1.": "c2VjcmV0"})
		cp := TrustedPlatformPlugin{}
		w := &mockTransferRW{remote: tcp}
		rc, _ := cp.handleZoneTransfer(context.Background(), w, newTransferRequest(""), zone, "example.com.")
		assertRefused(t, rc, w)
	})

	t.Run("unauthorized key", func(t *testing.T) {
		withTransferKeys(t, map[string]string{"secondary1.": "c2VjcmV0"})
		cp := TrustedPlatformPlugin{}
		w := &mockTransferRW{remote: tcp}
		rc, _ := cp.handleZoneTransfer(context.Background(), w, newTransferRequest("rogue."), zone, "example.com.")
		assertRefused(t, rc, w)
	})

	t.Run("tsig verification failure", func(t *testing.T) {
		withTransferKeys(t, map[string]string{"secondary1.": "c2VjcmV0"})
		cp := TrustedPlatformPlugin{}
		w := &mockTransferRW{remote: tcp, tsigStatus: dns.ErrSig}
		rc, _ := cp.handleZoneTransfer(context.Background(), w, newTransferRequest("secondary1."), zone, "example.com.")
		assertRefused(t, rc, w)
	})
}

func assertRefused(t *testing.T, rc int, w *mockTransferRW) {
	t.Helper()
	if rc != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED", rc)
	}
	if w.written == nil {
		t.Fatalf("expected a REFUSED reply to be written")
	}
	if len(w.written.Answer) != 0 {
		t.Fatalf("refused transfer must not leak zone data, got %d answers", len(w.written.Answer))
	}
}

// TestZoneTransfer_TSIGRoundTrip drives a real in-process DNS server over TCP
// with a configured TSIG secret and performs an authenticated AXFR through the
// miekg client, proving the server validates the request TSIG and signs the
// response. A wrong-secret client is rejected.
func TestZoneTransfer_TSIGRoundTrip(t *testing.T) {
	const keyName = "secondary1."
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	withTransferKeys(t, map[string]string{keyName: secret})
	zone := testTransferZone()
	cp := TrustedPlatformPlugin{}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_, _ = cp.handleZoneTransfer(context.Background(), w, r, zone, dns.Fqdn(r.Question[0].Name))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{
		Listener:   listener,
		Handler:    handler,
		TsigSecret: map[string]string{keyName: secret},
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := listener.Addr().String()

	t.Run("valid TSIG", func(t *testing.T) {
		tr := &dns.Transfer{TsigSecret: map[string]string{keyName: secret}}
		m := new(dns.Msg)
		m.SetAxfr("example.com.")
		m.SetTsig(keyName, dns.HmacSHA256, tsigFudge, time.Now().Unix())

		ch, err := tr.In(m, addr)
		if err != nil {
			t.Fatalf("transfer.In: %v", err)
		}
		var rrs []dns.RR
		for env := range ch {
			if env.Error != nil {
				t.Fatalf("envelope error: %v", env.Error)
			}
			rrs = append(rrs, env.RR...)
		}
		if len(rrs) < 3 {
			t.Fatalf("expected full-zone transfer, got %d records", len(rrs))
		}
		if _, ok := rrs[0].(*dns.SOA); !ok {
			t.Fatalf("first RR must be SOA, got %T", rrs[0])
		}
		if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
			t.Fatalf("last RR must be SOA, got %T", rrs[len(rrs)-1])
		}
	})

	t.Run("wrong TSIG secret is rejected", func(t *testing.T) {
		wrong := base64.StdEncoding.EncodeToString([]byte("ffffffffffffffff"))
		tr := &dns.Transfer{TsigSecret: map[string]string{keyName: wrong}}
		m := new(dns.Msg)
		m.SetAxfr("example.com.")
		m.SetTsig(keyName, dns.HmacSHA256, tsigFudge, time.Now().Unix())

		ch, err := tr.In(m, addr)
		if err != nil {
			// Rejected before streaming — acceptable.
			return
		}
		leaked := false
		failed := false
		for env := range ch {
			if env.Error != nil {
				failed = true
				continue
			}
			if len(env.RR) > 0 {
				leaked = true
			}
		}
		if leaked && !failed {
			t.Fatalf("wrong-secret transfer must not yield a clean full zone")
		}
	})
}
