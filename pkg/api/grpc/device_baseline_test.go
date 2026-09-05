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

package grpc

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestEntityPCRBaselineToProto_MapsEveryField pins the read-side mapping:
// indices become the unsigned wire keys, digests travel verbatim, and the
// source, timestamp and seeding device come across.
func TestEntityPCRBaselineToProto_MapsEveryField(t *testing.T) {
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	pb := EntityPCRBaselineToProto(&entities.PCRBaseline{
		Values:               map[int][]byte{0: {0xaa, 0xbb}, 7: {0x01}, -1: {0xff}},
		Source:               entities.BaselineSourceTOFU,
		RecordedAt:           recorded,
		RecordedFromDeviceID: 9007199254740993,
	})
	if pb == nil {
		t.Fatal("expected a pb baseline")
	}
	if got := pb.GetValues(); len(got) != 2 || string(got[0]) != "\xaa\xbb" || string(got[7]) != "\x01" {
		t.Fatalf("values not mapped (negative index must be dropped): %v", got)
	}
	if pb.GetSource() != "tofu" {
		t.Fatalf("source = %q", pb.GetSource())
	}
	if pb.GetRecordedAt() == nil || !pb.GetRecordedAt().AsTime().Equal(recorded) {
		t.Fatalf("recorded_at = %v", pb.GetRecordedAt())
	}
	if pb.GetRecordedFromDeviceId() != 9007199254740993 {
		t.Fatalf("recorded_from_device_id = %d", pb.GetRecordedFromDeviceId())
	}
}

// TestEntityPCRBaselineToProto_AbsentStaysAbsent proves a profile with no
// baseline sends none, and a baseline with no timestamp sends no timestamp,
// so a client cannot mistake "nothing recorded" for "recorded at epoch".
func TestEntityPCRBaselineToProto_AbsentStaysAbsent(t *testing.T) {
	if EntityPCRBaselineToProto(nil) != nil {
		t.Fatal("nil baseline must map to nil, not an empty message")
	}
	pb := EntityPCRBaselineToProto(&entities.PCRBaseline{Source: entities.BaselineSourceSigned})
	if pb == nil || pb.GetRecordedAt() != nil || len(pb.GetValues()) != 0 {
		t.Fatalf("unset fields must stay unset: %+v", pb)
	}
}
