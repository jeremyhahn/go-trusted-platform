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

package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// PublishRecords writes pre-derived TLSA records verbatim and re-signs the zone
// once. It must perform NO cert derivation.
func TestPublishRecords_WritesAndResigns(t *testing.T) {
	ctx := context.Background()
	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, testDANEConfig(false), daneTestLogger())

	records := []*entities.TLSARecord{
		{Name: "_443._tcp.host.example.com.", Usage: 2, Selector: 1, MatchingType: 1, Data: "aabbcc", TTL: 3600},
		{Name: "_443._tcp.host.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "ddeeff", TTL: 3600},
	}

	if err := publisher.PublishRecords(ctx, "example.com.", records); err != nil {
		t.Fatalf("PublishRecords: %v", err)
	}

	if len(svc.addedRecords) != 2 {
		t.Fatalf("expected 2 records written, got %d", len(svc.addedRecords))
	}
	// Data must be taken verbatim (no derivation).
	if svc.addedRecords[0].Data != "aabbcc" || svc.addedRecords[1].Data != "ddeeff" {
		t.Fatalf("records were not written verbatim: %+v", svc.addedRecords)
	}
	if svc.saveSignCalls != 1 {
		t.Errorf("expected exactly 1 SaveAndSign call, got %d", svc.saveSignCalls)
	}
}

// An empty record set is a no-op: no writes, no re-sign.
func TestPublishRecords_EmptyNoOp(t *testing.T) {
	ctx := context.Background()
	svc := newTestDNSService()
	publisher := NewDANEPublisher(svc, testDANEConfig(false), daneTestLogger())

	if err := publisher.PublishRecords(ctx, "example.com.", nil); err != nil {
		t.Fatalf("PublishRecords(nil): %v", err)
	}
	if len(svc.addedRecords) != 0 || svc.saveSignCalls != 0 {
		t.Fatalf("empty publish must be a no-op, got %d records / %d resigns",
			len(svc.addedRecords), svc.saveSignCalls)
	}
}

// A failed record write surfaces ErrDANEPublishFailed and aborts before re-sign.
func TestPublishRecords_AddError(t *testing.T) {
	ctx := context.Background()
	svc := newTestDNSService()
	svc.addErr = errors.New("write boom")
	publisher := NewDANEPublisher(svc, testDANEConfig(false), daneTestLogger())

	records := []*entities.TLSARecord{{Name: "_443._tcp.h.example.com.", Data: "aa", TTL: 1}}
	err := publisher.PublishRecords(ctx, "example.com.", records)
	if err == nil {
		t.Fatal("expected error from AddTLSARecord failure, got nil")
	}
	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Fatalf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
	if svc.saveSignCalls != 0 {
		t.Errorf("re-sign must not run after a write failure, got %d calls", svc.saveSignCalls)
	}
}

// A SaveAndSign failure surfaces ErrDANEPublishFailed.
func TestPublishRecords_SaveAndSignError(t *testing.T) {
	ctx := context.Background()
	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}
	svc.saveSignErr = errors.New("sign boom")
	publisher := NewDANEPublisher(svc, testDANEConfig(false), daneTestLogger())

	records := []*entities.TLSARecord{{Name: "_443._tcp.h.example.com.", Data: "aa", TTL: 1}}
	err := publisher.PublishRecords(ctx, "example.com.", records)
	if err == nil {
		t.Fatal("expected error from SaveAndSign failure, got nil")
	}
	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Fatalf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

// A missing zone (Zone lookup error) surfaces ErrDANEPublishFailed.
func TestPublishRecords_ZoneNotFound(t *testing.T) {
	ctx := context.Background()
	svc := newTestDNSService()
	// AddTLSARecord is allowed to succeed by pre-seeding nothing? The test
	// double fails AddTLSARecord on missing zone, so seed it then force Zone
	// to fail to isolate the Zone-lookup branch.
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}
	svc.zoneErr = errors.New("zone lookup boom")
	publisher := NewDANEPublisher(svc, testDANEConfig(false), daneTestLogger())

	records := []*entities.TLSARecord{{Name: "_443._tcp.h.example.com.", Data: "aa", TTL: 1}}
	err := publisher.PublishRecords(ctx, "example.com.", records)
	if err == nil {
		t.Fatal("expected error from Zone lookup failure, got nil")
	}
	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Fatalf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}
