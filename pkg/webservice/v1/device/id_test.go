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

package device

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aboveFloat64Precision is 2^53 + 1 — the smallest integer a JavaScript number
// cannot represent. Every assertion in this file uses it, because every one of
// them passes at small values whatever the encoding is.
const aboveFloat64Precision = uint64(9007199254740993)

// TestReadModifyWriteRoundTripAboveFloat64Precision is the assertion #342
// exists for: a client reads an object and writes it back, and the id survives.
//
// Before the ID type there was no correct move above 2^53. Responses carried
// `json:"id,string"` and requests a bare uint64, so echoing the string produced
// HTTP 400 before any handler ran, and converting it to a JavaScript number
// first lost precision — and the server then accepted a DIFFERENT id without
// complaint, which is an update applied to the wrong record.
//
// Mutations: revert DeviceResponse.ID to `uint64` with `json:"id,string"` and
// the round trip still passes (both sides speak strings); revert
// DeviceRequest.ID to a bare `uint64` and the unmarshal fails. Revert BOTH and
// the marshal emits a JSON number, which the numeric-precision assertion below
// catches.
func TestReadModifyWriteRoundTripAboveFloat64Precision(t *testing.T) {
	// 1. The server sends a device.
	sent, err := json.Marshal(DeviceResponse{ID: ID(aboveFloat64Precision)})
	require.NoError(t, err)

	// 2. It is a JSON *string*, so a JavaScript client keeps every digit.
	assert.Contains(t, string(sent), `"id":"9007199254740993"`,
		"the id must be a JSON string; a number at this magnitude loses precision in any JS client")

	// 3. The client echoes exactly what it received into a request.
	var back DeviceRequest
	require.NoError(t, json.Unmarshal(sent, &back),
		"the server must accept the id encoding it just produced — this is the round trip")

	// 4. And it is the same id, not an adjacent one.
	assert.Equal(t, aboveFloat64Precision, back.ID.Uint64())
}

// TestRequestsStillAcceptNumericIDs is the compatibility half, and the reason
// this is a widening rather than a break.
//
// Every client today sends numeric ids. Adding `,string` to the request types
// — the obvious repair — would have rejected all of them: encoding/json's
// `,string` accepts a quoted value and refuses a bare number outright.
func TestRequestsStillAcceptNumericIDs(t *testing.T) {
	var req DeviceRequest
	require.NoError(t, json.Unmarshal([]byte(`{"id":9007199254740993}`), &req),
		"a numeric id must still decode, or every existing client breaks")
	assert.Equal(t, aboveFloat64Precision, req.ID.Uint64())
}

// TestIDRejectsWhatIsNotAnUnsignedInteger: a wrong id must fail loudly rather
// than land on a neighbouring record.
func TestIDRejectsWhatIsNotAnUnsignedInteger(t *testing.T) {
	for name, body := range map[string]string{
		"text":     `{"id":"abc"}`,
		"negative": `{"id":-1}`,
		"float":    `{"id":1.5}`,
		"exponent": `{"id":"1e9"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var req DeviceRequest
			err := json.Unmarshal([]byte(body), &req)
			require.Error(t, err)

			var invalid ErrInvalidID
			assert.True(t, errors.As(err, &invalid), "want ErrInvalidID, got %T", err)
			assert.Zero(t, req.ID, "a rejected id must not be partially applied")
		})
	}
}

// TestIDTreatsNullAndEmptyAsAbsent pins the two encodings a client uses for
// "no id", so neither becomes an error and neither becomes a real id.
func TestIDTreatsNullAndEmptyAsAbsent(t *testing.T) {
	for _, body := range []string{`{"id":null}`, `{"id":""}`} {
		var req DeviceRequest
		require.NoError(t, json.Unmarshal([]byte(body), &req), body)
		assert.Zero(t, req.ID.Uint64(), body)
	}
}

// TestOmitEmptyStillElidesAZeroID guards the one behaviour a custom marshaller
// could silently change. `omitempty` is evaluated against the Go value before
// MarshalJSON is consulted, so a zero ID must still vanish from the output —
// verified rather than reasoned about, because a regression here would add an
// `"id":"0"` to every request body that omits one.
func TestOmitEmptyStillElidesAZeroID(t *testing.T) {
	withZero, err := json.Marshal(DeviceRequest{})
	require.NoError(t, err)
	assert.NotContains(t, string(withZero), `"id"`,
		"omitempty must still elide a zero id")

	withValue, err := json.Marshal(DeviceRequest{ID: ID(aboveFloat64Precision)})
	require.NoError(t, err)
	assert.Contains(t, string(withValue), `"id":"9007199254740993"`)
}

// TestEveryDeviceIDFieldSpeaksTheSameEncoding walks the four response and five
// request types together.
//
// The surface previously had THREE spellings of one concept — `json:"id,string"`
// on four responses, a bare uint64 on five requests, and a Go string filled by
// strconv.FormatUint on a sixth. A reader sweeping for `,string` finds four of
// them and stops. This asserts the encoding rather than the spelling, so a
// future field that reintroduces any of the three is caught by behaviour.
func TestEveryDeviceIDFieldSpeaksTheSameEncoding(t *testing.T) {
	id := ID(aboveFloat64Precision)
	const wantJSON = `"9007199254740993"`

	for name, v := range map[string]any{
		"DeviceResponse":        DeviceResponse{ID: id},
		"ProfileFullResponse":   ProfileFullResponse{ID: id},
		"TemplateResponse":      TemplateResponse{ID: id},
		"DeviceRequest":         DeviceRequest{ID: id},
		"DeviceRequestPayload":  DeviceRequestPayload{ID: id},
		"ProfileRequest":        ProfileRequest{ID: id},
		"TemplateRequest":       TemplateRequest{ID: id},
		"TemplateRequestNested": TemplateRequestNested{ID: id},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := json.Marshal(v)
			require.NoError(t, err)
			assert.Contains(t, string(out), `"id":`+wantJSON,
				"%s must emit the id as a JSON string like every other type on this surface", name)
		})
	}
}
