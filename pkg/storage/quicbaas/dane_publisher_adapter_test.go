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

package quicbaas

import (
	"context"
	"errors"
	"strings"
	"testing"

	xkmsdane "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/dane"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// fakeRecordWriter captures PublishRecords calls for assertion. It satisfies
// the narrow DANERecordWriter interface the adapter depends on.
type fakeRecordWriter struct {
	calls    []writeCall
	writeErr error
}

type writeCall struct {
	zone    string
	records []*entities.TLSARecord
}

func (w *fakeRecordWriter) PublishRecords(_ context.Context, zone string, records []*entities.TLSARecord) error {
	w.calls = append(w.calls, writeCall{zone: zone, records: records})
	return w.writeErr
}

// zoneSuffixResolver resolves a TLSA owner name to its zone by stripping the
// "_port._proto." prefix and matching against a known zone suffix.
func zoneSuffixResolver(zone string) DANEZoneResolver {
	return func(tlsaName string) (string, error) {
		name := strings.TrimSuffix(tlsaName, ".")
		for i := 0; i < 2 && strings.HasPrefix(name, "_"); i++ {
			if idx := strings.IndexByte(name, '.'); idx >= 0 {
				name = name[idx+1:]
			}
		}
		if strings.HasSuffix(name+".", "."+zone) || name+"." == zone {
			return zone, nil
		}
		return "", errors.New("no zone for " + tlsaName)
	}
}

func sampleRecord(name string) xkmsdane.Record {
	return xkmsdane.Record{
		Name:         name,
		Usage:        2,
		Selector:     1,
		MatchingType: 1,
		Data:         "deadbeef",
		TTL:          3600,
	}
}

// PublishDANE maps SDK records verbatim onto entities.TLSARecord and writes them
// through the backend's record writer, resolving the zone first.
func TestDANEAdapter_PublishDANE_WritesRecords(t *testing.T) {
	writer := &fakeRecordWriter{}
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, zoneSuffixResolver("example.com.")
	})

	rec := sampleRecord("_443._tcp.host.example.com.")
	if err := adapter.PublishDANE(context.Background(), []xkmsdane.Record{rec}); err != nil {
		t.Fatalf("PublishDANE: %v", err)
	}

	if len(writer.calls) != 1 {
		t.Fatalf("expected 1 PublishRecords call, got %d", len(writer.calls))
	}
	call := writer.calls[0]
	if call.zone != "example.com." {
		t.Errorf("zone = %q, want example.com.", call.zone)
	}
	if len(call.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(call.records))
	}
	got := call.records[0]
	if got.Name != rec.Name || got.Usage != rec.Usage || got.Selector != rec.Selector ||
		got.MatchingType != rec.MatchingType || got.Data != rec.Data || got.TTL != rec.TTL {
		t.Errorf("record not mapped verbatim: got %+v want %+v", got, rec)
	}
}

// Records spanning multiple zones are grouped so each zone is written (and thus
// re-signed) exactly once.
func TestDANEAdapter_PublishDANE_GroupsByZone(t *testing.T) {
	writer := &fakeRecordWriter{}
	// Resolver maps by the trailing two labels.
	resolver := func(tlsaName string) (string, error) {
		name := strings.TrimSuffix(tlsaName, ".")
		for i := 0; i < 2 && strings.HasPrefix(name, "_"); i++ {
			if idx := strings.IndexByte(name, '.'); idx >= 0 {
				name = name[idx+1:]
			}
		}
		parts := strings.Split(name, ".")
		if len(parts) < 2 {
			return "", errors.New("bad name")
		}
		return strings.Join(parts[len(parts)-2:], ".") + ".", nil
	}
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, resolver
	})

	records := []xkmsdane.Record{
		sampleRecord("_443._tcp.a.example.com."),
		sampleRecord("_443._tcp.b.example.com."),
		sampleRecord("_443._tcp.c.other.org."),
	}
	if err := adapter.PublishDANE(context.Background(), records); err != nil {
		t.Fatalf("PublishDANE: %v", err)
	}

	if len(writer.calls) != 2 {
		t.Fatalf("expected 2 grouped PublishRecords calls, got %d", len(writer.calls))
	}
	// example.com. should carry 2 records, other.org. 1.
	counts := map[string]int{}
	for _, c := range writer.calls {
		counts[c.zone] = len(c.records)
	}
	if counts["example.com."] != 2 {
		t.Errorf("example.com. records = %d, want 2", counts["example.com."])
	}
	if counts["other.org."] != 1 {
		t.Errorf("other.org. records = %d, want 1", counts["other.org."])
	}
}

// An empty record set is a no-op and never touches the backend.
func TestDANEAdapter_PublishDANE_EmptyNoOp(t *testing.T) {
	writer := &fakeRecordWriter{}
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, zoneSuffixResolver("example.com.")
	})
	if err := adapter.PublishDANE(context.Background(), nil); err != nil {
		t.Fatalf("PublishDANE(nil): %v", err)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("empty publish must not call the backend, got %d calls", len(writer.calls))
	}
}

// When no backend is wired, PublishDANE fails closed with the typed error.
func TestDANEAdapter_PublishDANE_NoBackend(t *testing.T) {
	adapter := NewDANEPublisherAdapter(nil)
	err := adapter.PublishDANE(context.Background(), []xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")})
	if err == nil {
		t.Fatal("expected ErrDANEPublisherNotAvailable, got nil")
	}
	var nf ErrDANEPublisherNotAvailable
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrDANEPublisherNotAvailable, got %T: %v", err, err)
	}
}

// A backend that returns nil components is treated as not-yet-wired.
func TestDANEAdapter_PublishDANE_BackendReturnsNil(t *testing.T) {
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return nil, nil
	})
	err := adapter.PublishDANE(context.Background(), []xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")})
	var nf ErrDANEPublisherNotAvailable
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrDANEPublisherNotAvailable, got %T: %v", err, err)
	}
}

// An unresolvable zone surfaces ErrDANEZoneUnresolved and never writes.
func TestDANEAdapter_PublishDANE_ZoneUnresolved(t *testing.T) {
	writer := &fakeRecordWriter{}
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, zoneSuffixResolver("example.com.")
	})
	err := adapter.PublishDANE(context.Background(),
		[]xkmsdane.Record{sampleRecord("_443._tcp.h.unknown.test.")})
	if err == nil {
		t.Fatal("expected ErrDANEZoneUnresolved, got nil")
	}
	var ze ErrDANEZoneUnresolved
	if !errors.As(err, &ze) {
		t.Fatalf("expected ErrDANEZoneUnresolved, got %T: %v", err, err)
	}
	if len(writer.calls) != 0 {
		t.Errorf("no records must be written on zone resolution failure, got %d calls", len(writer.calls))
	}
}

// A write failure from the backend is surfaced to the caller.
func TestDANEAdapter_PublishDANE_WriteError(t *testing.T) {
	writer := &fakeRecordWriter{writeErr: errors.New("write boom")}
	adapter := NewDANEPublisherAdapter(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, zoneSuffixResolver("example.com.")
	})
	err := adapter.PublishDANE(context.Background(),
		[]xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")})
	if err == nil || !strings.Contains(err.Error(), "write boom") {
		t.Fatalf("expected write error to propagate, got %v", err)
	}
}

// SetBackend installs a backend on an adapter constructed without one, and
// clearing it (nil) restores the fail-closed behavior.
func TestDANEAdapter_SetBackend(t *testing.T) {
	writer := &fakeRecordWriter{}
	adapter := NewDANEPublisherAdapter(nil)

	adapter.SetBackend(func() (DANERecordWriter, DANEZoneResolver) {
		return writer, zoneSuffixResolver("example.com.")
	})
	if err := adapter.PublishDANE(context.Background(),
		[]xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")}); err != nil {
		t.Fatalf("PublishDANE after SetBackend: %v", err)
	}
	if len(writer.calls) != 1 {
		t.Fatalf("expected 1 write after SetBackend, got %d", len(writer.calls))
	}

	adapter.SetBackend(nil)
	err := adapter.PublishDANE(context.Background(),
		[]xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")})
	var nf ErrDANEPublisherNotAvailable
	if !errors.As(err, &nf) {
		t.Fatalf("expected fail-closed after clearing backend, got %T: %v", err, err)
	}
}

// The error types render and unwrap as documented.
func TestDANEAdapter_ErrorTypes(t *testing.T) {
	cause := errors.New("root cause")
	ze := ErrDANEZoneUnresolved{Name: "_443._tcp.h.example.com.", Cause: cause}
	if !strings.Contains(ze.Error(), "_443._tcp.h.example.com.") {
		t.Errorf("ErrDANEZoneUnresolved.Error missing name: %q", ze.Error())
	}
	if !errors.Is(ze, cause) {
		t.Error("ErrDANEZoneUnresolved must unwrap to its cause")
	}
	zeNoCause := ErrDANEZoneUnresolved{Name: "x"}
	if !strings.Contains(zeNoCause.Error(), "x") {
		t.Errorf("ErrDANEZoneUnresolved.Error (no cause) missing name: %q", zeNoCause.Error())
	}
	if (ErrDANEPublisherNotAvailable{}).Error() == "" {
		t.Error("ErrDANEPublisherNotAvailable.Error must be non-empty")
	}
}

// The adapter satisfies the SDK DANEPublisher contract.
func TestDANEAdapter_ImplementsSDKInterface(t *testing.T) {
	var _ interface {
		PublishDANE(ctx context.Context, records []xkmsdane.Record) error
	} = (*DANEPublisherAdapter)(nil)
}

// A nil adapter is safe: SetBackend is a no-op and PublishDANE fails closed.
func TestDANEAdapter_NilReceiver(t *testing.T) {
	var adapter *DANEPublisherAdapter
	adapter.SetBackend(func() (DANERecordWriter, DANEZoneResolver) { return nil, nil })
	err := adapter.PublishDANE(context.Background(),
		[]xkmsdane.Record{sampleRecord("_443._tcp.h.example.com.")})
	var nf ErrDANEPublisherNotAvailable
	if !errors.As(err, &nf) {
		t.Fatalf("nil adapter must fail closed, got %T: %v", err, err)
	}
}
