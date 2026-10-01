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

package gateway

import (
	"errors"
	"testing"
	"time"
)

// statusJSON is what the REST route and the MCP tool send: the bare status
// object (pkg/api/rest.NAT64StatusResponse), including the REST-only
// timestamp the reply has no field for.
const statusJSON = `{
	"active": true,
	"instance_present": true,
	"prefix": "64:ff9b::/96",
	"instance": "tp-nat64",
	"sessions": 12,
	"pool4_used": 7,
	"module_version": "4.1.14",
	"flow_count": 5,
	"last_reconcile": "2026-10-01T12:00:00Z",
	"last_error": "pool4 display: busy",
	"timestamp": "2026-10-01T12:00:05Z"
}`

func TestDecodeNAT64StatusJSON_CarriesEveryField(t *testing.T) {
	resp, err := DecodeNAT64StatusJSON([]byte(statusJSON))
	if err != nil {
		t.Fatalf("DecodeNAT64StatusJSON() = %v", err)
	}
	s := resp.GetStatus()
	if s == nil {
		t.Fatal("the reply carries no status")
	}
	if !s.GetActive() || !s.GetInstancePresent() || s.GetPrefix() != "64:ff9b::/96" || s.GetInstance() != "tp-nat64" {
		t.Fatalf("identity fields lost: %+v", s)
	}
	if s.GetSessions() != 12 || s.GetPool4Used() != 7 || s.GetFlowCount() != 5 {
		t.Fatalf("counters lost: %+v", s)
	}
	if s.GetModuleVersion() != "4.1.14" || s.GetLastError() != "pool4 display: busy" {
		t.Fatalf("version or last error lost: %+v", s)
	}
	if want := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC); !s.GetLastReconcile().AsTime().Equal(want) {
		t.Fatalf("last_reconcile = %v, want %v", s.GetLastReconcile().AsTime(), want)
	}
}

func TestDecodeNAT64StatusJSON_LeavesANeverConvergedServiceUnset(t *testing.T) {
	// The server's time.Time has no omitempty that works on a struct, so a
	// service that never converged sends year 1. That is "never", not a
	// timestamp a caller should render.
	resp, err := DecodeNAT64StatusJSON([]byte(`{"active":false,"last_reconcile":"0001-01-01T00:00:00Z"}`))
	if err != nil {
		t.Fatalf("DecodeNAT64StatusJSON() = %v", err)
	}
	if resp.GetStatus().GetLastReconcile() != nil {
		t.Fatalf("last_reconcile = %v, want unset", resp.GetStatus().GetLastReconcile())
	}
}

func TestDecodeNAT64StatusJSON_RefusesWhatIsNotTheStatusObject(t *testing.T) {
	for name, payload := range map[string]string{
		"not json":     `{"active":`,
		"a list":       `[{"active":true}]`,
		"a wrong type": `{"sessions":"many"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeNAT64StatusJSON([]byte(payload))
			var typed *ErrNAT64StatusDecodeFailed
			if !errors.As(err, &typed) || typed.Unwrap() == nil {
				t.Fatalf("DecodeNAT64StatusJSON(%s) = %v, want *ErrNAT64StatusDecodeFailed with its cause", payload, err)
			}
		})
	}
}
