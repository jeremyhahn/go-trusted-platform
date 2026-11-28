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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// eventLogTestEvent builds a parsed event with one sha256 digest. The digest
// is an unnamed struct literal so the test needs no import of the lower
// module that names the digest type.
func eventLogTestEvent(num, pcr int, eventType, digestHex string) xkmssdk.TPMEvent {
	ev := xkmssdk.TPMEvent{
		EventNum:    num,
		PCRIndex:    pcr,
		EventType:   eventType,
		DigestCount: 1,
		EventSize:   16,
		EventString: "test",
	}
	ev.Digests = append(ev.Digests, struct {
		AlgorithmId string
		Digest      string
	}{AlgorithmId: "sha256", Digest: digestHex})
	return ev
}

func callEventLog(t *testing.T, mock *mockTPM) TPM2EventLogResponse {
	t.Helper()
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2EventLog}})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	var out TPM2EventLogResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	return out
}

// gRPC and REST GetEventLog answer the parsed entries; QUIC 0x13 must answer
// the same fields (docs/SPEC.md:78, #2069).
func TestTPM2Handler_HandleEventLog_AnswersEntries(t *testing.T) {
	mock := newMockTPM()
	mock.parsedEvents = []xkmssdk.TPMEvent{
		eventLogTestEvent(0, 0, "EV_S_CRTM_VERSION", strings.Repeat("ab", 32)),
		eventLogTestEvent(1, 7, "EV_EFI_VARIABLE_DRIVER_CONFIG", strings.Repeat("cd", 32)),
	}

	out := callEventLog(t, mock)
	assert.Equal(t, uint64(2), out.EventCount)
	require.Len(t, out.Entries, 2)
	for i, ev := range mock.parsedEvents {
		got := out.Entries[i]
		assert.Equal(t, uint32(ev.EventNum), got.EventNum)
		assert.Equal(t, uint32(ev.PCRIndex), got.PCRIndex)
		assert.Equal(t, ev.EventType, got.EventType)
		assert.Equal(t, uint32(ev.DigestCount), got.DigestCount)
		assert.Equal(t, uint32(ev.EventSize), got.EventSize)
		assert.Equal(t, ev.EventString, got.EventString)
		require.Len(t, got.Digests, 1)
		assert.Equal(t, ev.Digests[0].AlgorithmId, got.Digests[0].AlgorithmID)
		assert.Equal(t, ev.Digests[0].Digest, got.Digests[0].Digest)
		assert.Len(t, got.Digests[0].Digest, 64)
	}
}

// A raw log that does not parse still answers the raw bytes, with no entries.
func TestTPM2Handler_HandleEventLog_UnparsableHasNoEntries(t *testing.T) {
	mock := newMockTPM()
	mock.parsedEventsErr = errors.New("unparsable event log")

	out := callEventLog(t, mock)
	assert.NotEmpty(t, out.EventLog)
	assert.Empty(t, out.Entries)
	assert.Zero(t, out.EventCount)
}
