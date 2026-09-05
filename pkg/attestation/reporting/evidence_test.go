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

package reporting

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func envelope(t *testing.T, att map[string]any) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"status": "STATUS_OK", "attestation": att})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"success": true, "code": 200, "payload": json.RawMessage(payload)})
	require.NoError(t, err)
	return body
}

func goodAttestation(nonce []byte) map[string]any {
	return map[string]any{
		"quoteData": b64s([]byte("TPMS_ATTEST")),
		"signature": b64s([]byte("sig")),
		"pcrs": []map[string]any{
			{"index": 0, "value": b64s([]byte("pcr0"))},
			{"index": 7, "value": b64s([]byte("pcr7"))},
		},
		"pcrDigest":   b64s([]byte("digest")),
		"nonce":       b64s(nonce),
		"akPublicKey": b64s([]byte("ak")),
	}
}

func TestDecodeHostAttestation_ProducesVerifierEvidence(t *testing.T) {
	nonce := []byte("nonce-1")
	ev, err := decodeHostAttestation(envelope(t, goodAttestation(nonce)), nonce)
	require.NoError(t, err)
	assert.Equal(t, []byte("TPMS_ATTEST"), ev.Quote)
	assert.Equal(t, []byte("sig"), ev.Signature)
	assert.Equal(t, nonce, ev.Nonce)
	assert.Equal(t, map[int][]byte{0: []byte("pcr0"), 7: []byte("pcr7")}, ev.PCRs)

	encoded, err := ev.Encode()
	require.NoError(t, err)
	// The verifier's contract: four fields, these names, base64 bytes,
	// PCR keys as decimal strings.
	var wire map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &wire))
	assert.ElementsMatch(t, []string{"quote", "signature", "nonce", "pcrs"}, keys(wire))
	var pcrs map[string]string
	require.NoError(t, json.Unmarshal(wire["pcrs"], &pcrs))
	assert.Equal(t, b64s([]byte("pcr7")), pcrs["7"])
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDecodeHostAttestation_RefusesWrongNonce(t *testing.T) {
	body := envelope(t, goodAttestation([]byte("other")))
	_, err := decodeHostAttestation(body, []byte("nonce-1"))
	require.Error(t, err)
	var mismatch ErrNonceMismatch
	assert.ErrorAs(t, err, &mismatch)
}

func TestDecodeHostAttestation_RefusesMalformedResponses(t *testing.T) {
	nonce := []byte("n")
	cases := map[string][]byte{
		"not json":         []byte("<html>"),
		"failure envelope": []byte(`{"success":false,"code":500,"error":{"message":"x"}}`),
		"no payload":       []byte(`{"success":true,"code":200}`),
		"payload not obj":  []byte(`{"success":true,"code":200,"payload":"x"}`),
		"no attestation":   []byte(`{"success":true,"code":200,"payload":{}}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := decodeHostAttestation(body, nonce)
			require.Error(t, err)
			var invalid ErrInvalidEvidence
			assert.ErrorAs(t, err, &invalid)
		})
	}

	mutate := func(f func(m map[string]any)) []byte {
		m := goodAttestation(nonce)
		f(m)
		return envelope(t, m)
	}
	fieldCases := map[string][]byte{
		"empty quote":   mutate(func(m map[string]any) { m["quoteData"] = "" }),
		"bad base64":    mutate(func(m map[string]any) { m["signature"] = "!!" }),
		"bad nonce":     mutate(func(m map[string]any) { m["nonce"] = "!!" }),
		"no pcrs":       mutate(func(m map[string]any) { m["pcrs"] = []any{} }),
		"bad pcr value": mutate(func(m map[string]any) { m["pcrs"] = []map[string]any{{"index": 1, "value": "!!"}} }),
		"duplicate pcr": mutate(func(m map[string]any) {
			m["pcrs"] = []map[string]any{{"index": 1, "value": b64s([]byte("a"))}, {"index": 1, "value": b64s([]byte("b"))}}
		}),
		"empty pcr value": mutate(func(m map[string]any) { m["pcrs"] = []map[string]any{{"index": 1, "value": ""}} }),
	}
	for name, body := range fieldCases {
		t.Run(name, func(t *testing.T) {
			_, err := decodeHostAttestation(body, nonce)
			require.Error(t, err)
			var invalid ErrInvalidEvidence
			assert.ErrorAs(t, err, &invalid, err.Error())
		})
	}
}

func TestEvidence_EncodeRequiresEveryField(t *testing.T) {
	var nilEv *Evidence
	_, err := nilEv.Encode()
	require.Error(t, err)
	_, err = (&Evidence{Quote: []byte("q")}).Encode()
	require.Error(t, err)
	var invalid ErrInvalidEvidence
	assert.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Error(), "required")
}

func TestEqualBytes(t *testing.T) {
	assert.True(t, equalBytes([]byte("a"), []byte("a")))
	assert.False(t, equalBytes([]byte("a"), []byte("b")))
	assert.False(t, equalBytes([]byte("a"), []byte("ab")))
	assert.True(t, equalBytes(nil, nil))
}
