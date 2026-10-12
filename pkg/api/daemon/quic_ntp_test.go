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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newNTPQUICHandler builds a QUIC handler wired to a scripted NTP backend.
func newNTPQUICHandler(backend NTPBackend) *QUICServiceHandler {
	handler := NewQUICServiceHandler(logging.DefaultLogger())
	if backend != nil {
		handler.SetNTPService(NewNTPGRPCService(nil, backend))
	}
	return handler
}

// ntpCategoryRequest builds a category request carrying only the sub-opcode,
// which is exactly what the SDK adapter sends for the empty-bodied NTP
// methods.
func ntpCategoryRequest(sub byte) *quicwire.Request {
	return &quicwire.Request{Opcode: quicwire.OpNTPCategory, Payload: []byte{sub}}
}

func TestQUICNTPCategoryServesEverySubOperation(t *testing.T) {
	backend := &fakeNTPBackend{
		status:     syncedNTPStatus(),
		sources:    ntpTestSources(),
		stepStatus: syncedNTPStatus(),
	}
	handler := newNTPQUICHandler(backend)
	ctx := context.Background()

	t.Run("get status", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, ntpCategoryRequest(quicwire.NTPSubGetStatus))
		if resp.Status != quicwire.StatusOK {
			t.Fatalf("status = 0x%02x, payload %q", resp.Status, resp.Payload)
		}
		var decoded platformv1.GetNTPStatusResponse
		if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !decoded.GetStatus().GetSynced() || decoded.GetStatus().GetStratum() != 3 {
			t.Fatalf("decoded = %+v, want synced stratum 3", decoded.GetStatus())
		}
	})

	t.Run("list sources", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, ntpCategoryRequest(quicwire.NTPSubListSources))
		if resp.Status != quicwire.StatusOK {
			t.Fatalf("status = 0x%02x, payload %q", resp.Status, resp.Payload)
		}
		var decoded platformv1.ListNTPSourcesResponse
		if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded.GetSources()) != 2 {
			t.Fatalf("len(sources) = %d, want 2", len(decoded.GetSources()))
		}
		if decoded.GetSources()[0].GetAddress() != "10.4.200.1" {
			t.Fatalf("source[0].Address = %q, want 10.4.200.1", decoded.GetSources()[0].GetAddress())
		}
	})

	t.Run("step", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, ntpCategoryRequest(quicwire.NTPSubStep))
		if resp.Status != quicwire.StatusOK {
			t.Fatalf("status = 0x%02x, payload %q", resp.Status, resp.Payload)
		}
		if backend.stepCalls != 1 {
			t.Fatalf("step calls = %d, want 1", backend.stepCalls)
		}
	})
}

func TestQUICNTPCategoryRejectsBadRequests(t *testing.T) {
	t.Run("no backend", func(t *testing.T) {
		handler := newNTPQUICHandler(nil)
		resp := handler.HandleRequest(context.Background(), ntpCategoryRequest(quicwire.NTPSubGetStatus))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x, want StatusUnavailable", resp.Status)
		}
	})

	t.Run("missing sub-opcode", func(t *testing.T) {
		handler := newNTPQUICHandler(&fakeNTPBackend{status: syncedNTPStatus()})
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpNTPCategory})
		if resp.Status != quicwire.StatusInvalidRequest {
			t.Fatalf("status = 0x%02x, want StatusInvalidRequest", resp.Status)
		}
	})

	t.Run("unknown sub-opcode", func(t *testing.T) {
		handler := newNTPQUICHandler(&fakeNTPBackend{status: syncedNTPStatus()})
		resp := handler.HandleRequest(context.Background(), ntpCategoryRequest(0x7F))
		if resp.Status != quicwire.StatusNotImplemented {
			t.Fatalf("status = 0x%02x, want StatusNotImplemented", resp.Status)
		}
	})
}

func TestQUICNTPStepReportsConflictWithNoReachableSource(t *testing.T) {
	backend := &fakeNTPBackend{stepErr: ntp.ErrNoReachableSource{Total: 2}}
	handler := newNTPQUICHandler(backend)

	resp := handler.HandleRequest(context.Background(), ntpCategoryRequest(quicwire.NTPSubStep))
	// StatusAlreadyExists is the wire's conflict status, mirroring the
	// REST 409 contract for this condition.
	if resp.Status != quicwire.StatusAlreadyExists {
		t.Fatalf("status = 0x%02x, want StatusAlreadyExists (conflict)", resp.Status)
	}
}

func TestQUICNTPPropagatesControlFailures(t *testing.T) {
	backend := &fakeNTPBackend{
		statusErr:  ntp.ErrControlUnavailable{Command: "tracking"},
		sourcesErr: ntp.ErrControlUnavailable{Command: "sources"},
	}
	handler := newNTPQUICHandler(backend)
	ctx := context.Background()

	for _, sub := range []byte{quicwire.NTPSubGetStatus, quicwire.NTPSubListSources} {
		resp := handler.HandleRequest(ctx, ntpCategoryRequest(sub))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("sub 0x%02x status = 0x%02x, want StatusUnavailable", sub, resp.Status)
		}
	}
}

func TestWithQUICNTPServiceOptionWiresTheBackend(t *testing.T) {
	service := NewNTPGRPCService(nil, &fakeNTPBackend{status: syncedNTPStatus()})
	handler := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICNTPService(service))

	resp := handler.HandleRequest(context.Background(), ntpCategoryRequest(quicwire.NTPSubGetStatus))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, want StatusOK", resp.Status)
	}
}
