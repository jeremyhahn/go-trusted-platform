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
	"strconv"
	"strings"
	"testing"
	"time"
)

// logServiceOptions shapes the mock LogServices tree.
type logServiceOptions struct {
	// services lists LogService resources under /redfish/v1/Systems/1/LogServices.
	services []redfishLogService
	// pages maps an Entries path to the collection it serves.
	pages map[string]redfishLogEntryCollection
	// noLogServices makes the collection 404 (old firmware).
	noLogServices bool
}

// newMockRedfishLogServer serves the discovery routes plus a LogServices
// tree; it reuses the standard mock's service-root and system shapes.
func newMockRedfishLogServer(t *testing.T, opts logServiceOptions) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishServiceRoot{
			ODataID: "/redfish/v1/", RedfishVersion: "1.0.0",
			Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
			Chassis:  redfishRef{ODataID: "/redfish/v1/Chassis"},
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Systems/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Chassis", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Chassis/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"Id": "1"})
	})
	mux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishSystem{Manufacturer: "Supermicro", Model: "Super Server", PowerState: "On"})
	})
	mux.HandleFunc("/redfish/v1/Systems/1/LogServices", func(w http.ResponseWriter, r *http.Request) {
		if opts.noLogServices {
			http.NotFound(w, r)
			return
		}
		members := make([]redfishRef, 0, len(opts.services))
		for i := range opts.services {
			members = append(members, redfishRef{ODataID: "/redfish/v1/Systems/1/LogServices/" + opts.services[i].ID})
		}
		writeJSON(w, redfishCollection{Members: members})
	})
	for i := range opts.services {
		svc := opts.services[i]
		mux.HandleFunc("/redfish/v1/Systems/1/LogServices/"+svc.ID, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, svc)
		})
	}
	// Pages are keyed by "path" or "path?query" so @odata.nextLink paging
	// (a query on the same path) can be modelled with one handler per path.
	byPath := make(map[string]struct{})
	for key := range opts.pages {
		byPath[strings.SplitN(key, "?", 2)[0]] = struct{}{}
	}
	for path := range byPath {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			key := r.URL.Path
			if r.URL.RawQuery != "" {
				key += "?" + r.URL.RawQuery
			}
			page, ok := opts.pages[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, page)
		})
	}
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRedfishGetEventLog_ReadsPagedSEL(t *testing.T) {
	const entries = "/redfish/v1/Systems/1/LogServices/Log1/Entries"
	srv := newMockRedfishLogServer(t, logServiceOptions{
		services: []redfishLogService{
			{ID: "Audit", Name: "Audit Log", LogEntryType: "Event"},
			{ID: "Log1", Name: "System Event Log", LogEntryType: "SEL", OverWritePolicy: "NeverOverWrites",
				MaxNumberOfRecords: 3, Entries: redfishRef{ODataID: entries}},
		},
		pages: map[string]redfishLogEntryCollection{
			entries: {
				MembersCount: 3,
				NextLink:     entries + "?$skip=2",
				Members: []redfishLogEntry{
					{ID: "1", Created: "2024-04-20T10:00:00Z", EntryType: "SEL", EntryCode: "Assert",
						Severity: "Warning", SensorType: "Memory", SensorNumber: float64(26),
						Message: "Correctable ECC | Asserted"},
					{ID: "2", Created: "2024-04-20T10:05:00Z", EntryType: "SEL", EntryCode: "Assert",
						Severity: "Critical", SensorType: "Event Logging Disabled", SensorNumber: "0x40",
						Message: "Log full"},
				},
			},
			entries + "?$skip=2": {
				MembersCount: 3,
				Members: []redfishLogEntry{
					{ID: "3", Created: "2024-04-21T00:00:00Z", EntryType: "SEL", EntryCode: "Deassert",
						SensorType: "Memory", SensorNumber: "#26", Message: "Uncorrectable ECC | Deasserted"},
				},
			},
		},
	})
	client := newTestRedfishClient(t, srv)

	log, err := client.GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(log.Entries) != 3 || log.EntryCount != 3 {
		t.Fatalf("expected 3 entries across two pages, got %d (count %d)", len(log.Entries), log.EntryCount)
	}
	if !log.Overflow {
		t.Error("3 of MaxNumberOfRecords=3 with NeverOverWrites is full")
	}
	if log.FreeBytes != -1 {
		t.Errorf("Redfish exposes no free space; FreeBytes = %d", log.FreeBytes)
	}
	if !log.LastAddition.Equal(time.Date(2024, 4, 21, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("last addition = %v", log.LastAddition)
	}

	first := log.Entries[0]
	if first.SensorTypeCode != SensorTypeMemory || first.SensorNumber != 26 || first.EventOffset != MemoryEventCorrectableECC || !first.IsMemoryFault() {
		t.Errorf("first entry: %+v", first)
	}
	second := log.Entries[1]
	if second.SensorTypeCode != SensorTypeEventLoggingDisabled || second.SensorNumber != 0x40 || !second.IsLogFull() {
		t.Errorf("second entry: %+v", second)
	}
	third := log.Entries[2]
	if third.Asserted || third.SensorNumber != 26 || third.EventOffset != MemoryEventUncorrectableECC || third.IsMemoryFault() {
		t.Errorf("a DMTF Deassert memory entry is not an active fault: %+v", third)
	}
	if !log.Full() || len(log.MemoryFaults()) != 1 {
		t.Errorf("classification: full=%v faults=%d", log.Full(), len(log.MemoryFaults()))
	}
}

func TestParseRedfishLogEntry_EntryCodes(t *testing.T) {
	for code, asserted := range map[string]bool{"Assert": true, "Deassert": false, "assert": true, "Deasserted": false, "": true} {
		e := parseRedfishLogEntry(&redfishLogEntry{SensorType: "Memory", Message: "Uncorrectable ECC", EntryCode: code})
		if e.Asserted != asserted {
			t.Errorf("EntryCode %q: Asserted = %v, want %v", code, e.Asserted, asserted)
		}
		if e.IsMemoryFault() != asserted {
			t.Errorf("EntryCode %q: IsMemoryFault = %v, want %v", code, e.IsMemoryFault(), asserted)
		}
	}
}

func TestRedfishGetEventLog_WrapsWhenFullIsNotOverflow(t *testing.T) {
	const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
	srv := newMockRedfishLogServer(t, logServiceOptions{
		services: []redfishLogService{{ID: "SEL", OverWritePolicy: "WrapsWhenFull", MaxNumberOfRecords: 1,
			Entries: redfishRef{ODataID: entries}}},
		pages: map[string]redfishLogEntryCollection{entries: {Members: []redfishLogEntry{{ID: "1", Message: "x"}}}},
	})
	log, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log.Overflow || log.EntryCount != 1 {
		t.Errorf("a wrapping log at capacity is not overflowed: %+v", log)
	}
}

func TestRedfishGetEventLog_Unsupported(t *testing.T) {
	t.Run("no LogServices collection", func(t *testing.T) {
		srv := newMockRedfishLogServer(t, logServiceOptions{noLogServices: true})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var unsupported ErrUnsupportedOperation
		if !errors.As(err, &unsupported) {
			t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
		}
	})
	t.Run("no SEL among services", func(t *testing.T) {
		srv := newMockRedfishLogServer(t, logServiceOptions{services: []redfishLogService{{ID: "Audit", LogEntryType: "Event"}}})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var unsupported ErrUnsupportedOperation
		if !errors.As(err, &unsupported) {
			t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
		}
	})
	t.Run("closed client", func(t *testing.T) {
		srv := newMockRedfishLogServer(t, logServiceOptions{})
		client := newTestRedfishClient(t, srv)
		client.closed.Store(true)
		_, err := client.GetEventLog(context.Background())
		var closed ErrClientClosed
		if !errors.As(err, &closed) {
			t.Fatalf("expected ErrClientClosed, got %v", err)
		}
	})
}

func TestRedfishGetEventLog_Errors(t *testing.T) {
	t.Run("entries page fails", func(t *testing.T) {
		srv := newMockRedfishLogServer(t, logServiceOptions{
			services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: "/redfish/v1/Systems/1/LogServices/SEL/Missing"}}},
		})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var readErr ErrEventLogRead
		if !errors.As(err, &readErr) {
			t.Fatalf("expected ErrEventLogRead, got %v", err)
		}
	})
	t.Run("service without Entries link", func(t *testing.T) {
		srv := newMockRedfishLogServer(t, logServiceOptions{services: []redfishLogService{{ID: "SEL"}}})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var readErr ErrEventLogRead
		if !errors.As(err, &readErr) {
			t.Fatalf("expected ErrEventLogRead, got %v", err)
		}
	})
	t.Run("repeated next link is an error", func(t *testing.T) {
		const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
		srv := newMockRedfishLogServer(t, logServiceOptions{
			services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: entries}}},
			pages: map[string]redfishLogEntryCollection{entries: {
				NextLink: entries, Members: []redfishLogEntry{{ID: "1", SensorType: "Memory", Message: "Parity | Asserted"}},
			}},
		})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var paging ErrEventLogPaging
		if !errors.As(err, &paging) || paging.Link != entries || paging.Pages != 1 {
			t.Fatalf("a repeated page must fail the read, not return a partial log: %v", err)
		}
	})
	t.Run("page bound with another page advertised is an error", func(t *testing.T) {
		const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
		pages := make(map[string]redfishLogEntryCollection)
		link := entries
		for i := 0; i <= redfishMaxLogPages; i++ {
			next := entries + "?$skip=" + strconv.Itoa(i+1)
			pages[link] = redfishLogEntryCollection{NextLink: next, Members: []redfishLogEntry{{ID: strconv.Itoa(i), Message: "x"}}}
			link = next
		}
		srv := newMockRedfishLogServer(t, logServiceOptions{
			services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: entries}}},
			pages:    pages,
		})
		_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
		var paging ErrEventLogPaging
		if !errors.As(err, &paging) || paging.Pages != redfishMaxLogPages {
			t.Fatalf("exhausting the page bound with more pages advertised must fail: %v", err)
		}
	})
}

func TestRedfishGetEventLog_SortsOldestFirst(t *testing.T) {
	const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
	srv := newMockRedfishLogServer(t, logServiceOptions{
		services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: entries}}},
		pages: map[string]redfishLogEntryCollection{entries: {Members: []redfishLogEntry{
			{ID: "3", Created: "2024-04-22T00:00:00Z", Message: "newest"},
			{ID: "u1", Message: "undated first"},
			{ID: "2", Created: "2024-04-21T00:00:00Z", Message: "middle"},
			{ID: "u2", Message: "undated second"},
			{ID: "1", Created: "2024-04-20T00:00:00Z", Message: "oldest"},
		}}},
	})
	log, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for _, e := range log.Entries {
		got = append(got, e.ID)
	}
	want := "u1,u2,1,2,3"
	if strings.Join(got, ",") != want {
		t.Errorf("order = %s, want %s (undated first in service order, then oldest to newest)", strings.Join(got, ","), want)
	}
	if !log.LastAddition.Equal(time.Date(2024, 4, 22, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("last addition = %v", log.LastAddition)
	}
}

func TestRedfishGetEventLog_EntryCapFlagsTruncation(t *testing.T) {
	const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
	members := make([]redfishLogEntry, selMaxEntries+5)
	for i := range members {
		members[i] = redfishLogEntry{ID: strconv.Itoa(i), Message: "x"}
	}
	srv := newMockRedfishLogServer(t, logServiceOptions{
		services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: entries}}},
		pages:    map[string]redfishLogEntryCollection{entries: {MembersCount: selMaxEntries + 5, Members: members}},
	})
	log, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(log.Entries) != selMaxEntries || !log.Truncated || log.EntryCount != selMaxEntries+5 {
		t.Fatalf("cap must truncate and say so: entries=%d truncated=%v count=%d", len(log.Entries), log.Truncated, log.EntryCount)
	}
}

func TestParseRedfishLogEntry_Lenient(t *testing.T) {
	entry := parseRedfishLogEntry(&redfishLogEntry{
		ID: "9", Created: "not-a-time", SensorType: "Unicorn", SensorNumber: "0x1A", Message: "whatever",
	})
	if !entry.Timestamp.IsZero() || entry.SensorTypeCode != 0 || entry.SensorNumber != 0x1A || entry.EventOffset != 0xFF || !entry.Asserted {
		t.Errorf("lenient parse: %+v", entry)
	}
	if parseSensorNumberString("300") != 0 || parseSensorNumberString("zz") != 0 || parseSensorNumberString("") != 0 {
		t.Error("invalid sensor numbers must decode to 0")
	}
	limit := parseRedfishLogEntry(&redfishLogEntry{SensorType: "Memory", Message: "Correctable ECC logging limit reached | Asserted"})
	if limit.EventOffset != MemoryEventCorrectableLimit {
		t.Errorf("longest description must win, got offset %#x", limit.EventOffset)
	}
	if eventOffsetFromMessage(0x07, "Correctable ECC") != 0xFF {
		t.Error("only memory and logging types are text-matched")
	}
	if eventOffsetFromMessage(SensorTypeEventLoggingDisabled, "Correctable memory error logging disabled | Asserted") != LoggingEventCorrectableMemoryDisabled {
		t.Error("the full IPMI description must beat the 'logging disabled' alias")
	}
	if eventOffsetFromMessage(SensorTypeEventLoggingDisabled, "Log almost full") != LoggingEventSELAlmostFull {
		t.Error("Supermicro 'Log almost full' alias")
	}
}

func TestRedfishGetEventLog_OversizedPageRejected(t *testing.T) {
	const entries = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
	huge := redfishLogEntryCollection{Members: make([]redfishLogEntry, 0, 1)}
	for i := 0; i < 50000; i++ {
		huge.Members = append(huge.Members, redfishLogEntry{ID: "x", Message: strings.Repeat("m", 100)})
	}
	srv := newMockRedfishLogServer(t, logServiceOptions{
		services: []redfishLogService{{ID: "SEL", Entries: redfishRef{ODataID: entries}}},
		pages:    map[string]redfishLogEntryCollection{entries: huge},
	})
	_, err := newTestRedfishClient(t, srv).GetEventLog(context.Background())
	var readErr ErrEventLogRead
	if !errors.As(err, &readErr) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a page over maxLogPageBytes must be rejected before decoding, got %v", err)
	}
}
