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

package app

import (
	"context"
	"errors"
	"testing"

	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// fakeBMCZoneStore serves one zone and records what the dns-register step
// saved back.
type fakeBMCZoneStore struct {
	zone      *dnsentities.Zone
	zoneErr   error
	saveErr   error
	askedName string
	saved     *dnsentities.Zone
}

func (f *fakeBMCZoneStore) Zone(_ context.Context, name string) (*dnsentities.Zone, error) {
	f.askedName = name
	if f.zoneErr != nil {
		return nil, f.zoneErr
	}
	return f.zone, nil
}

func (f *fakeBMCZoneStore) Save(_ context.Context, zone *dnsentities.Zone) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = zone
	return nil
}

func internalZoneWith(records ...*dnsentities.ARecord) *dnsentities.Zone {
	return &dnsentities.Zone{
		Name:      "internal.example.",
		RecordSet: dnsentities.RecordSet{ARecords: records},
	}
}

// The BMC's A record lands in the platform's own internal zone: the step does
// not go through caller-driven dynamic registration, so dns.allow-registration
// does not refuse it.
func TestRegisterBMCRecord_AddsTheRecordToTheInternalZone(t *testing.T) {
	store := &fakeBMCZoneStore{zone: internalZoneWith()}

	fqdn, err := registerBMCRecord(context.Background(), store, "10.0.0.5", "10.0.0.5", "internal.example.")
	if err != nil {
		t.Fatalf("registerBMCRecord: %v", err)
	}
	if fqdn != "10.0.0.5-bmc.internal.example." {
		t.Errorf("fqdn = %q, want 10.0.0.5-bmc.internal.example.", fqdn)
	}
	if store.askedName != "internal.example." {
		t.Errorf("zone looked up = %q, want internal.example.", store.askedName)
	}
	if store.saved == nil {
		t.Fatal("zone was not saved")
	}
	records := store.saved.RecordSet.ARecords
	if len(records) != 1 || records[0].Name != "10.0.0.5-bmc" || records[0].Value != "10.0.0.5" {
		t.Fatalf("A records = %+v, want one 10.0.0.5-bmc -> 10.0.0.5", records)
	}
}

// Re-enrolling a BMC whose address changed moves its record instead of adding
// a second one.
func TestRegisterBMCRecord_ReEnrollmentKeepsOneRecord(t *testing.T) {
	store := &fakeBMCZoneStore{zone: internalZoneWith(
		&dnsentities.ARecord{Name: "ns1", Value: "10.0.0.1", TTL: 3600},
		&dnsentities.ARecord{Name: "node1-bmc", Value: "10.0.0.9", TTL: 3600},
	)}

	if _, err := registerBMCRecord(context.Background(), store, "node1", "10.0.0.5", "internal.example"); err != nil {
		t.Fatalf("registerBMCRecord: %v", err)
	}
	records := store.saved.RecordSet.ARecords
	if len(records) != 2 {
		t.Fatalf("A records = %+v, want ns1 and one node1-bmc", records)
	}
	if records[1].Name != "node1-bmc" || records[1].Value != "10.0.0.5" {
		t.Errorf("node1-bmc record = %+v, want value 10.0.0.5", records[1])
	}
}

func TestRegisterBMCRecord_RefusesAnAddressThatIsNotIPv4(t *testing.T) {
	for _, address := range []string{"bmc1.example", "", "fd00::5"} {
		store := &fakeBMCZoneStore{zone: internalZoneWith()}
		_, err := registerBMCRecord(context.Background(), store, "bmc1", address, "internal.example.")
		var addrErr ErrBMCDNSInvalidAddress
		if !errors.As(err, &addrErr) {
			t.Errorf("address %q: err = %v, want ErrBMCDNSInvalidAddress", address, err)
		}
		if store.saved != nil {
			t.Errorf("address %q: zone saved, want no write", address)
		}
	}
}

func TestRegisterBMCRecord_ReturnsZoneLookupAndSaveFailures(t *testing.T) {
	lookupErr := errors.New("zone not found")
	store := &fakeBMCZoneStore{zoneErr: lookupErr}
	if _, err := registerBMCRecord(context.Background(), store, "bmc1", "10.0.0.5", "internal.example."); !errors.Is(err, lookupErr) {
		t.Errorf("lookup failure: err = %v, want %v", err, lookupErr)
	}

	saveErr := errors.New("datastore down")
	store = &fakeBMCZoneStore{zone: internalZoneWith(), saveErr: saveErr}
	if _, err := registerBMCRecord(context.Background(), store, "bmc1", "10.0.0.5", "internal.example."); !errors.Is(err, saveErr) {
		t.Errorf("save failure: err = %v, want %v", err, saveErr)
	}
}
