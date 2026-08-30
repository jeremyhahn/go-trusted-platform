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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// redfishLogServicesSuffix is the LogServices collection under a System.
const redfishLogServicesSuffix = "/LogServices"

// redfishMaxLogPages bounds an Entries walk over @odata.nextLink so a
// BMC that keeps handing out the same page cannot spin the reader.
const redfishMaxLogPages = 64

// maxLogPageBytes bounds one Entries page before it is decoded. A page
// of a few hundred LogEntry resources is well under 1 MiB; the cap is what
// keeps a hostile BMC from dictating the reader's memory.
const maxLogPageBytes = 4 << 20

// redfishLogService is a LogService resource (DSP2046 LogService).
type redfishLogService struct {
	ID                 string     `json:"Id"`
	Name               string     `json:"Name"`
	LogEntryType       string     `json:"LogEntryType"`
	OverWritePolicy    string     `json:"OverWritePolicy"`
	MaxNumberOfRecords int        `json:"MaxNumberOfRecords"`
	Entries            redfishRef `json:"Entries"`
}

// redfishLogEntryCollection is the Entries collection, with the two
// members needed to page through it.
type redfishLogEntryCollection struct {
	Members      []redfishLogEntry `json:"Members"`
	MembersCount int               `json:"Members@odata.count"`
	NextLink     string            `json:"Members@odata.nextLink"`
}

// redfishLogEntry is a LogEntry resource (DSP2046 LogEntry). SensorNumber
// is untyped in the wild — Supermicro returns an integer, some firmwares
// a string — so it is decoded leniently.
type redfishLogEntry struct {
	ID           string `json:"Id"`
	Created      string `json:"Created"`
	EntryType    string `json:"EntryType"`
	EntryCode    string `json:"EntryCode"`
	Message      string `json:"Message"`
	Severity     string `json:"Severity"`
	SensorType   string `json:"SensorType"`
	SensorNumber any    `json:"SensorNumber"`
}

// GetEventLog reads the SEL through the System's LogServices collection:
// the service whose LogEntryType is "SEL" (or whose Id says so), then
// its Entries, paged through @odata.nextLink. A BMC with no LogServices
// link, or no SEL among them, returns ErrUnsupportedOperation — the
// capability is genuinely absent, not unimplemented here.
func (c *redfishClient) GetEventLog(ctx context.Context) (*EventLog, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, err
	}
	systemPath := c.getSystemPath()
	if systemPath == "" {
		return nil, ErrUnsupportedOperation{Operation: "event log (no Redfish system)"}
	}

	var services redfishCollection
	if err := c.doGET(ctx, systemPath+redfishLogServicesSuffix, &services); err != nil {
		var reqErr ErrRedfishRequest
		if errors.As(err, &reqErr) && reqErr.StatusCode == http.StatusNotFound {
			return nil, ErrUnsupportedOperation{Operation: "event log (no LogServices)"}
		}
		return nil, ErrEventLogRead{Operation: "log services", Cause: err}
	}

	var sel *redfishLogService
	for _, member := range services.Members {
		var svc redfishLogService
		if err := c.doGET(ctx, member.ODataID, &svc); err != nil {
			return nil, ErrEventLogRead{Operation: "log service " + member.ODataID, Cause: err}
		}
		if isSELService(&svc) {
			sel = &svc
			break
		}
	}
	if sel == nil {
		return nil, ErrUnsupportedOperation{Operation: "event log (no SEL log service)"}
	}
	if sel.Entries.ODataID == "" {
		return nil, ErrEventLogRead{Operation: "log service " + sel.ID, Cause: ErrRedfishRequest{
			Method: "GET", Path: sel.ID, Cause: ErrUnsupportedOperation{Operation: "log service has no Entries link"}}}
	}

	log := &EventLog{FreeBytes: -1}
	next := sel.Entries.ODataID
	seen := make(map[string]struct{}, redfishMaxLogPages)
	pages := 0
	for next != "" && !log.Truncated {
		if pages >= redfishMaxLogPages {
			return nil, ErrEventLogRead{Operation: "log entries", Cause: ErrEventLogPaging{Link: next, Pages: pages}}
		}
		if _, dup := seen[next]; dup {
			// A service that keeps advertising the same page would loop
			// forever; the pages read so far are not the whole log.
			return nil, ErrEventLogRead{Operation: "log entries", Cause: ErrEventLogPaging{Link: next, Pages: pages}}
		}
		seen[next] = struct{}{}
		pages++
		var coll redfishLogEntryCollection
		if err := c.doGETBounded(ctx, next, &coll, maxLogPageBytes); err != nil {
			return nil, ErrEventLogRead{Operation: "log entries " + next, Cause: err}
		}
		if coll.MembersCount > log.EntryCount {
			log.EntryCount = coll.MembersCount
		}
		for i := range coll.Members {
			if len(log.Entries) >= selMaxEntries {
				log.Truncated = true
				c.logger.Warn("bmc: Redfish log truncated at the entry cap",
					slog.Int("cap", selMaxEntries))
				break
			}
			entry := parseRedfishLogEntry(&coll.Members[i])
			log.Entries = append(log.Entries, entry)
			if entry.Timestamp.After(log.LastAddition) {
				log.LastAddition = entry.Timestamp
			}
		}
		next = coll.NextLink
	}
	if log.EntryCount < len(log.Entries) {
		log.EntryCount = len(log.Entries)
	}
	// Services order their collections as they like; the contract is
	// oldest first. Entries without a timestamp keep their relative
	// order and sort ahead of dated ones.
	sort.SliceStable(log.Entries, func(i, j int) bool {
		return log.Entries[i].Timestamp.Before(log.Entries[j].Timestamp)
	})
	if sel.MaxNumberOfRecords > 0 && log.EntryCount >= sel.MaxNumberOfRecords && !strings.EqualFold(sel.OverWritePolicy, "WrapsWhenFull") {
		log.Overflow = true
	}
	return log, nil
}

// doGETBounded is doGET with the response body capped at limit bytes;
// a larger body is ErrRedfishRequest rather than a partial decode.
func (c *redfishClient) doGETBounded(ctx context.Context, path string, out any, limit int64) error {
	resp, err := c.transport.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// The error parser reads the whole body for its message; keep the
		// same cap on it so a hostile error page is bounded too.
		bounded := resp
		bounded.Body = io.NopCloser(io.LimitReader(resp.Body, limit))
		return parseRedfishError(bounded, http.MethodGet, path)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	if int64(len(body)) > limit {
		return ErrRedfishRequest{Method: http.MethodGet, Path: path, StatusCode: resp.StatusCode,
			Message: "response exceeds " + strconv.FormatInt(limit, 10) + " bytes"}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	return nil
}

// isSELService reports whether a LogService is the System Event Log.
func isSELService(svc *redfishLogService) bool {
	if strings.EqualFold(svc.LogEntryType, "SEL") {
		return true
	}
	id := strings.ToLower(svc.ID)
	return strings.Contains(id, "sel") || strings.Contains(strings.ToLower(svc.Name), "system event log")
}

// parseRedfishLogEntry maps a LogEntry onto EventLogEntry. The
// sensor-specific event offset is not on the wire in Redfish, so memory
// and logging faults are recognised from the Message text instead.
func parseRedfishLogEntry(e *redfishLogEntry) EventLogEntry {
	entry := EventLogEntry{
		ID:          e.ID,
		SensorType:  e.SensorType,
		Message:     e.Message,
		Asserted:    !isDeassertCode(e.EntryCode),
		EventOffset: 0xFF,
	}
	if e.Created != "" {
		if ts, err := time.Parse(time.RFC3339, e.Created); err == nil {
			entry.Timestamp = ts.UTC()
		}
	}
	if code, ok := SensorTypeCode(e.SensorType); ok {
		entry.SensorTypeCode = code
	}
	switch n := e.SensorNumber.(type) {
	case float64:
		if n >= 0 && n <= 255 {
			entry.SensorNumber = uint8(n)
		}
	case string:
		entry.SensorNumber = parseSensorNumberString(n)
	}
	entry.EventOffset = eventOffsetFromMessage(entry.SensorTypeCode, e.Message)
	return entry
}

// isDeassertCode reports whether a LogEntry EntryCode is the DMTF
// deassertion value ("Deassert", DSP8010 LogEntry.EntryCode) or the
// "Deasserted" spelling some firmware emits.
func isDeassertCode(code string) bool {
	return strings.EqualFold(code, "Deassert") || strings.EqualFold(code, "Deasserted")
}

// parseSensorNumberString accepts "12", "0x0C" and "#12" forms.
func parseSensorNumberString(s string) uint8 {
	s = strings.TrimSpace(strings.TrimPrefix(s, "#"))
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	var n uint8
	for _, r := range strings.ToLower(s) {
		var d int
		switch {
		case r >= '0' && r <= '9':
			d = int(r - '0')
		case base == 16 && r >= 'a' && r <= 'f':
			d = int(r-'a') + 10
		default:
			return 0
		}
		v := int(n)*base + d
		if v > 255 {
			return 0
		}
		n = uint8(v)
	}
	return n
}

// messageAlias is a BMC-specific phrasing of a sensor-specific event.
type messageAlias struct {
	text   string
	offset uint8
}

// loggingMessageAliases are the phrasings Supermicro firmware uses for
// the Event Logging Disabled sensor in place of the IPMI table names
// ("Log full" for "SEL full").
var loggingMessageAliases = []messageAlias{
	{"log full", LoggingEventSELFull},
	{"log almost full", LoggingEventSELAlmostFull},
	{"logging disabled", LoggingEventAllDisabled},
}

// eventOffsetFromMessage recovers the sensor-specific offset for the
// memory and logging sensor types from the BMC's message text, which is
// what the IPMI descriptions were written to match. Returns 0xFF when
// the text matches nothing.
func eventOffsetFromMessage(sensorType uint8, message string) uint8 {
	msg := strings.ToLower(message)
	var candidates []messageAlias
	switch sensorType {
	case SensorTypeMemory:
		for i, desc := range memoryEventDescriptions {
			candidates = append(candidates, messageAlias{desc, uint8(i)})
		}
	case SensorTypeEventLoggingDisabled:
		for i, desc := range loggingEventDescriptions {
			candidates = append(candidates, messageAlias{desc, uint8(i)})
		}
		candidates = append(candidates, loggingMessageAliases...)
	default:
		return 0xFF
	}
	// Longest match wins so "Correctable ECC logging limit reached" is
	// not claimed by "Correctable ECC", nor "Correctable memory error
	// logging disabled" by "logging disabled".
	best, bestLen := uint8(0xFF), 0
	for _, c := range candidates {
		if len(c.text) > bestLen && strings.Contains(msg, strings.ToLower(c.text)) {
			best, bestLen = c.offset, len(c.text)
		}
	}
	return best
}
