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

package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every PIV transport must (a) carry the PIN and key material to the backend
// in a MemoryEnclave rather than the deprecated plain field, and (b) wipe
// that enclave before the handler returns — on the error path as well as the
// success path. Dropping either the enclave assignment or the deferred
// Destroy has to fail here; the pre-existing adapter tests only inspect
// non-sensitive fields and would not notice.

// pivEnclaveProbe reads the protected fields while the call is in flight and
// keeps the request pointers so the test can assert on them afterwards, once
// the handler's deferred Destroy has run.
type pivEnclaveProbe struct {
	err error

	gen  *PIVGenerateRequest
	imp  *PIVImportRequest
	sign *PIVSignRequest

	genPIN    string
	importPEM string
	importPIN string
	signPIN   string
}

func (p *pivEnclaveProbe) ListDevices(context.Context) ([]PIVDevice, error) {
	return []PIVDevice{{ID: "dev"}}, p.err
}

func (p *pivEnclaveProbe) ListSlots(context.Context, string) ([]PIVSlot, error) {
	return []PIVSlot{{ID: "9a"}}, p.err
}

func (p *pivEnclaveProbe) SlotInfo(_ context.Context, _, slot string) (*PIVSlotInfo, error) {
	return &PIVSlotInfo{Slot: PIVSlot{ID: slot}}, p.err
}

func (p *pivEnclaveProbe) Generate(_ context.Context, req *PIVGenerateRequest) (*PIVGenerateResult, error) {
	p.gen = req
	if err := req.WithPIN(func(pin string) error {
		p.genPIN = pin
		return nil
	}); err != nil {
		return nil, err
	}
	if p.err != nil {
		return nil, p.err
	}
	return &PIVGenerateResult{PublicKeyPEM: "PUB"}, nil
}

func (p *pivEnclaveProbe) Import(_ context.Context, req *PIVImportRequest) error {
	p.imp = req
	if err := req.WithPrivateKeyPEM(func(pem []byte) error {
		p.importPEM = string(pem)
		return nil
	}); err != nil {
		return err
	}
	if err := req.WithPIN(func(pin string) error {
		p.importPIN = pin
		return nil
	}); err != nil {
		return err
	}
	return p.err
}

func (p *pivEnclaveProbe) Sign(_ context.Context, req *PIVSignRequest) ([]byte, error) {
	p.sign = req
	if err := req.WithPIN(func(pin string) error {
		p.signPIN = pin
		return nil
	}); err != nil {
		return nil, err
	}
	if p.err != nil {
		return nil, p.err
	}
	return []byte("SIG"), nil
}

func (p *pivEnclaveProbe) Attest(context.Context, string) (*PIVAttestResult, error) {
	return &PIVAttestResult{}, p.err
}

func (p *pivEnclaveProbe) Reset(context.Context, string) error { return p.err }

// assertGenerateWiped checks the generate request reached the backend through
// the enclave and was wiped afterwards.
func assertGenerateWiped(t *testing.T, p *pivEnclaveProbe, wantPIN string) {
	t.Helper()
	if p.gen == nil {
		t.Fatal("backend never saw a generate request")
	}
	if p.gen.PINEnclave == nil {
		t.Error("PINEnclave not populated; the transport passed the plain PIN")
	}
	if p.gen.PIN != "" {
		t.Errorf("deprecated PIN field = %q, want empty", p.gen.PIN)
	}
	if p.genPIN != wantPIN {
		t.Errorf("backend saw PIN %q, want %q", p.genPIN, wantPIN)
	}
	if p.gen.PINEnclave.IsAlive() {
		t.Error("PINEnclave still alive after the handler returned")
	}
}

func assertImportWiped(t *testing.T, p *pivEnclaveProbe, wantPEM, wantPIN string) {
	t.Helper()
	if p.imp == nil {
		t.Fatal("backend never saw an import request")
	}
	if p.imp.PrivateKey == nil || p.imp.PINEnclave == nil {
		t.Fatal("import enclaves not populated; the transport passed plain fields")
	}
	if p.imp.PrivateKeyPEM != "" {
		t.Errorf("deprecated PrivateKeyPEM = %q, want empty", p.imp.PrivateKeyPEM)
	}
	if p.importPEM != wantPEM {
		t.Errorf("backend saw PEM %q, want %q", p.importPEM, wantPEM)
	}
	if p.importPIN != wantPIN {
		t.Errorf("backend saw PIN %q, want %q", p.importPIN, wantPIN)
	}
	if p.imp.PrivateKey.IsAlive() {
		t.Error("PrivateKey enclave still alive after the handler returned")
	}
	if p.imp.PINEnclave.IsAlive() {
		t.Error("PINEnclave still alive after the handler returned")
	}
}

func assertSignWiped(t *testing.T, p *pivEnclaveProbe, wantPIN string) {
	t.Helper()
	if p.sign == nil {
		t.Fatal("backend never saw a sign request")
	}
	if p.sign.PINEnclave == nil {
		t.Error("PINEnclave not populated; the transport passed the plain PIN")
	}
	if p.sign.PIN != "" {
		t.Errorf("deprecated PIN field = %q, want empty", p.sign.PIN)
	}
	if p.signPIN != wantPIN {
		t.Errorf("backend saw PIN %q, want %q", p.signPIN, wantPIN)
	}
	if p.sign.PINEnclave.IsAlive() {
		t.Error("PINEnclave still alive after the handler returned")
	}
}

func newPIVProbeService(p *pivEnclaveProbe) *PIVService {
	return NewPIVService(logging.DefaultLogger(), p)
}

// --- REST ------------------------------------------------------------------

func pivRESTPost(t *testing.T, svc *PIVService, path, body string) int {
	t.Helper()
	router := mux.NewRouter()
	newPIVRESTHandlers(svc).registerPIVRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec.Code
}

func TestPIVREST_EnclaveLifecycle(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivRESTPost(t, newPIVProbeService(p), "/piv/slots/9a/generate",
			`{"algorithm":"RSA2048","pin":"111111"}`)
		assertGenerateWiped(t, p, "111111")
	})
	t.Run("import", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivRESTPost(t, newPIVProbeService(p), "/piv/slots/9a/import",
			`{"private_key_pem":"PEM","pin":"222222"}`)
		assertImportWiped(t, p, "PEM", "222222")
	})
	t.Run("sign", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivRESTPost(t, newPIVProbeService(p), "/piv/slots/9a/sign",
			`{"payload":"ZGF0YQ==","pin":"333333"}`)
		assertSignWiped(t, p, "333333")
	})
	t.Run("sign wipes on the error path", func(t *testing.T) {
		p := &pivEnclaveProbe{err: errors.New("backend down")}
		if code := pivRESTPost(t, newPIVProbeService(p), "/piv/slots/9a/sign",
			`{"payload":"ZGF0YQ==","pin":"444444"}`); code == http.StatusOK {
			t.Fatal("expected a failure status")
		}
		assertSignWiped(t, p, "444444")
	})
}

// --- gRPC (also the Unix transport, which serves this service over a UDS) ---

func TestPIVGRPC_EnclaveLifecycle(t *testing.T) {
	ctx := context.Background()

	t.Run("generate", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		svc := NewPIVGRPCService(logging.DefaultLogger(), newPIVProbeService(p))
		if _, err := svc.Generate(ctx, &platformv1.PIVGenerateRequest{
			Slot: "9a", Pin: "111111",
		}); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		assertGenerateWiped(t, p, "111111")
	})
	t.Run("import", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		svc := NewPIVGRPCService(logging.DefaultLogger(), newPIVProbeService(p))
		if _, err := svc.Import(ctx, &platformv1.PIVImportRequest{
			Slot: "9a", PrivateKeyPem: "PEM", Pin: "222222",
		}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		assertImportWiped(t, p, "PEM", "222222")
	})
	t.Run("sign", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		svc := NewPIVGRPCService(logging.DefaultLogger(), newPIVProbeService(p))
		if _, err := svc.Sign(ctx, &platformv1.PIVSignRequest{
			Slot: "9a", Payload: []byte("data"), Pin: "333333",
		}); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		assertSignWiped(t, p, "333333")
	})
	t.Run("import wipes on the error path", func(t *testing.T) {
		p := &pivEnclaveProbe{err: errors.New("backend down")}
		svc := NewPIVGRPCService(logging.DefaultLogger(), newPIVProbeService(p))
		if _, err := svc.Import(ctx, &platformv1.PIVImportRequest{
			Slot: "9a", PrivateKeyPem: "PEM", Pin: "444444",
		}); err == nil {
			t.Fatal("expected an error")
		}
		assertImportWiped(t, p, "PEM", "444444")
	})
}

// --- QUIC ------------------------------------------------------------------

func pivQUICCall(t *testing.T, svc *PIVService, sub byte, payload any) *quic.Response {
	t.Helper()
	raw, err := quic.EncodePayload(payload)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	h := &pivQUICHandlers{service: svc}
	return h.Handle(context.Background(), &quic.Request{
		Payload: append([]byte{sub}, raw...),
	})
}

func TestPIVQUIC_EnclaveLifecycle(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivQUICCall(t, newPIVProbeService(p), quic.PIVSubGenerate,
			&quic.PIVGenerateReq{Slot: "9a", Algorithm: "RSA2048", PIN: "111111"})
		assertGenerateWiped(t, p, "111111")
	})
	t.Run("import", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivQUICCall(t, newPIVProbeService(p), quic.PIVSubImport,
			&quic.PIVImportReq{Slot: "9a", PrivateKeyPEM: "PEM", PIN: "222222"})
		assertImportWiped(t, p, "PEM", "222222")
	})
	t.Run("sign", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		pivQUICCall(t, newPIVProbeService(p), quic.PIVSubSign,
			&quic.PIVSignReq{Slot: "9a", Payload: []byte("data"), PIN: "333333"})
		assertSignWiped(t, p, "333333")
	})
	t.Run("generate wipes on the error path", func(t *testing.T) {
		p := &pivEnclaveProbe{err: errors.New("backend down")}
		resp := pivQUICCall(t, newPIVProbeService(p), quic.PIVSubGenerate,
			&quic.PIVGenerateReq{Slot: "9a", PIN: "444444"})
		if resp.Status == quic.StatusOK {
			t.Fatal("expected a failure status")
		}
		assertGenerateWiped(t, p, "444444")
	})
}

// --- MCP -------------------------------------------------------------------

func newPIVMCPProvider(p *pivEnclaveProbe) *MCPServiceProvider {
	prov := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	prov.SetPhase35Services(Phase35Services{PIV: newPIVProbeService(p)})
	return prov
}

func TestPIVMCP_EnclaveLifecycle(t *testing.T) {
	ctx := context.Background()

	t.Run("generate", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		if _, err := newPIVMCPProvider(p).PIVGenerate(ctx, map[string]interface{}{
			"slot": "9a", "algorithm": "RSA2048", "pin": "111111",
		}); err != nil {
			t.Fatalf("PIVGenerate: %v", err)
		}
		assertGenerateWiped(t, p, "111111")
	})
	t.Run("import", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		if _, err := newPIVMCPProvider(p).PIVImport(ctx, map[string]interface{}{
			"slot": "9a", "private_key_pem": "PEM", "pin": "222222",
		}); err != nil {
			t.Fatalf("PIVImport: %v", err)
		}
		assertImportWiped(t, p, "PEM", "222222")
	})
	t.Run("sign", func(t *testing.T) {
		p := &pivEnclaveProbe{}
		if _, err := newPIVMCPProvider(p).PIVSign(ctx, map[string]interface{}{
			"slot": "9a", "payload": "ZGF0YQ==", "pin": "333333",
		}); err != nil {
			t.Fatalf("PIVSign: %v", err)
		}
		assertSignWiped(t, p, "333333")
	})
	t.Run("sign wipes on the error path", func(t *testing.T) {
		p := &pivEnclaveProbe{err: errors.New("backend down")}
		if _, err := newPIVMCPProvider(p).PIVSign(ctx, map[string]interface{}{
			"slot": "9a", "payload": "ZGF0YQ==", "pin": "444444",
		}); err == nil {
			t.Fatal("expected an error")
		}
		assertSignWiped(t, p, "444444")
	})
}
