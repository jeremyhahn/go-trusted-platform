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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// eventLogTPM is a TrustedPlatformModule holding a raw event log and the
// events its parser yields (or the parser's error).
type eventLogTPM struct {
	xkmssdk.TrustedPlatformModule
	raw      []byte
	events   []xkmssdk.TPMEvent
	parseErr error
}

func (t *eventLogTPM) EventLog() ([]byte, error) { return t.raw, nil }
func (t *eventLogTPM) ParsedEventLog() ([]xkmssdk.TPMEvent, error) {
	if t.parseErr != nil {
		return nil, t.parseErr
	}
	return t.events, nil
}

// twoTestEvents answers two parsed events. They are decoded from JSON so
// the test names no go-xkms package beyond the SDK alias.
func twoTestEvents(t *testing.T) []xkmssdk.TPMEvent {
	t.Helper()
	d0 := strings.Repeat("ab", 32)
	d7 := strings.Repeat("cd", 32)
	doc := `[
		{"EventNum":0,"PCRIndex":0,"EventType":"EV_S_CRTM_VERSION","DigestCount":1,
		 "Digests":[{"AlgorithmId":"sha256","Digest":"` + d0 + `"}],"EventSize":16,"EventString":"test"},
		{"EventNum":1,"PCRIndex":7,"EventType":"EV_EFI_VARIABLE_DRIVER_CONFIG","DigestCount":1,
		 "Digests":[{"AlgorithmId":"sha256","Digest":"` + d7 + `"}],"EventSize":16,"EventString":"test"}
	]`
	var events []xkmssdk.TPMEvent
	require.NoError(t, json.Unmarshal([]byte(doc), &events))
	require.Len(t, events, 2)
	return events
}

func TestTPMParity_EventLogEntries(t *testing.T) {
	ctx := context.Background()
	tpm := &eventLogTPM{raw: []byte("raw-tcg2-log"), events: twoTestEvents(t)}
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	resp, err := grpcSvc.GetEventLog(ctx, &platformv1.GetEventLogRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEntries(), 2)

	got, err := mcp.TPMEventLog(ctx)
	require.NoError(t, err)
	result, ok := got.(map[string]interface{})
	require.True(t, ok, "MCP answers a map, got %T", got)
	assert.Equal(t, 2, result["event_count"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(tpm.raw), result["event_log"])

	entries, ok := result["entries"].([]map[string]interface{})
	require.True(t, ok, "MCP entries is []map[string]interface{}, got %T", result["entries"])
	require.Len(t, entries, 2)

	for i, want := range resp.GetEntries() {
		e := entries[i]
		assert.Equal(t, want.GetEventNum(), e["event_num"], "entry %d event_num", i)
		assert.Equal(t, want.GetPcrIndex(), e["pcr_index"], "entry %d pcr_index", i)
		assert.Equal(t, want.GetEventType(), e["event_type"], "entry %d event_type", i)
		assert.Equal(t, want.GetDigestCount(), e["digest_count"], "entry %d digest_count", i)
		assert.Equal(t, want.GetEventSize(), e["event_size"], "entry %d event_size", i)
		assert.Equal(t, want.GetEventString(), e["event_string"], "entry %d event_string", i)

		digests, ok := e["digests"].([]map[string]interface{})
		require.True(t, ok, "entry %d digests is []map[string]interface{}, got %T", i, e["digests"])
		require.Len(t, digests, len(want.GetDigests()))
		for j, wd := range want.GetDigests() {
			assert.Equal(t, wd.GetAlgorithmId(), digests[j]["algorithm_id"], "entry %d digest %d algorithm_id", i, j)
			assert.Equal(t, wd.GetDigest(), digests[j]["digest"], "entry %d digest %d digest", i, j)
		}
	}
	assert.Equal(t, uint32(7), resp.GetEntries()[1].GetPcrIndex())
	assert.Equal(t, "EV_EFI_VARIABLE_DRIVER_CONFIG", resp.GetEntries()[1].GetEventType())
}

func TestTPMParity_EventLogUnparsable(t *testing.T) {
	ctx := context.Background()
	tpm := &eventLogTPM{raw: []byte("not-a-log"), parseErr: errors.New("unparsable event log")}
	grpcSvc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)

	resp, err := grpcSvc.GetEventLog(ctx, &platformv1.GetEventLogRequest{})
	require.NoError(t, err)
	assert.Equal(t, tpm.raw, resp.GetEventLog())
	assert.Empty(t, resp.GetEntries())

	got, err := mcp.TPMEventLog(ctx)
	require.NoError(t, err)
	result, ok := got.(map[string]interface{})
	require.True(t, ok, "MCP answers a map, got %T", got)
	assert.Equal(t, base64.StdEncoding.EncodeToString(tpm.raw), result["event_log"])
	if entries, present := result["entries"]; present {
		assert.Empty(t, entries)
	}
	_, hasCount := result["event_count"]
	assert.False(t, hasCount)
}
