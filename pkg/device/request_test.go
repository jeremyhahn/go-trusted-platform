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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullDevice is the entity every field of fullFields maps onto.
var fullDevice = &entities.Device{
	ID:         42,
	AttestPub:  "attest-pub",
	AttestCert: "attest-cert",
	EKCert:     "ek-cert",
	EventLog:   []byte{1, 2, 3},
	HashAlgoId: 11,
	Model:      "model",
	Serial:     "SN-1",
	SigningPub: "signing-pub",
	SwitchName: "sw1",
	SwitchPort: "ge-0/0/1",
}

const fullFields = `"id":"42","attest_pub":"attest-pub","attest_cert":"attest-cert",` +
	`"ek_cert":"ek-cert","event_log":"AQID","hash_algo_id":11,"model":"model",` +
	`"serial":"SN-1","signing_pub":"signing-pub","switch_name":"sw1","switch_port":"ge-0/0/1"`

func TestDecodeRequest_EveryShapeYieldsTheSameDevice(t *testing.T) {
	bodies := map[string]string{
		"flat":     `{` + fullFields + `}`,
		"envelope": `{"device":{` + fullFields + `}}`,
		"split": `{"id":"42","attest_pub":"attest-pub","event_log":"AQID","model":"model","serial":"SN-1",` +
			`"device":{"attest_cert":"attest-cert","ek_cert":"ek-cert","hash_algo_id":11,` +
			`"signing_pub":"signing-pub","switch_name":"sw1","switch_port":"ge-0/0/1"}}`,
		"both, agreeing": `{` + fullFields + `,"device":{` + fullFields + `}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeRequest(strings.NewReader(body))
			require.NoError(t, err)
			assert.Equal(t, fullDevice, got)
		})
	}
}

func TestDecodeRequest_IgnoresKeysTheEntityHasNoColumnFor(t *testing.T) {
	got, err := DecodeRequest(strings.NewReader(
		`{"serial":"SN-1","name":"rack-3","type":"server","device_type":"server",` +
			`"description":"d","version":"1","tpm_version":"2.0","tpm_manufacturer":"IFX"}`))

	require.NoError(t, err)
	assert.Equal(t, &entities.Device{Serial: "SN-1"}, got)
}

func TestDecodeRequest_ManufacturerStandsInForAnAbsentModel(t *testing.T) {
	got, err := DecodeRequest(strings.NewReader(`{"serial":"SN-1","manufacturer":"Dell"}`))
	require.NoError(t, err)
	assert.Equal(t, "Dell", got.Model)

	got, err = DecodeRequest(strings.NewReader(`{"serial":"SN-1","model":"R640","manufacturer":"Dell"}`))
	require.NoError(t, err)
	assert.Equal(t, "R640", got.Model, "an explicit model wins over the manufacturer")
}

func TestDecodeRequest_RefusesAConflict(t *testing.T) {
	cases := map[string]struct {
		body  string
		field string
	}{
		"string field": {`{"serial":"FLAT","device":{"serial":"NESTED"}}`, "serial"},
		"id":           {`{"id":1,"device":{"id":"2"}}`, "id"},
		"number field": {`{"hash_algo_id":11,"device":{"hash_algo_id":12}}`, "hash_algo_id"},
		"byte field":   {`{"event_log":"AQID","device":{"event_log":"BAUG"}}`, "event_log"},
		"first conflict wins": {
			`{"attest_pub":"a","serial":"b","device":{"attest_pub":"x","serial":"y"}}`, "attest_pub",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeRequest(strings.NewReader(tc.body))

			assert.Nil(t, got)
			assert.Equal(t, ErrDeviceRequestConflict{Field: tc.field}, err)
		})
	}
}

func TestDecodeRequest_RefusesAnUnreadableBody(t *testing.T) {
	for name, body := range map[string]string{
		"empty":        ``,
		"not JSON":     `serial=SN-1`,
		"wrong type":   `{"serial":7}`,
		"invalid id":   `{"id":-1}`,
		"array":        `[{"serial":"SN-1"}]`,
		"envelope str": `{"device":"SN-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeRequest(strings.NewReader(body))

			assert.Nil(t, got)
			var bodyErr ErrDeviceRequestBody
			require.ErrorAs(t, err, &bodyErr)
			assert.Error(t, bodyErr.Cause)
		})
	}
}

func TestDecodeCreateRequest_AcceptsABodyWithASerial(t *testing.T) {
	got, err := DecodeCreateRequest(strings.NewReader(`{"device":{"serial":"SN-1","model":"m"}}`))

	require.NoError(t, err)
	assert.Equal(t, &entities.Device{Serial: "SN-1", Model: "m"}, got)
}

func TestDecodeCreateRequest_RequiresASerial(t *testing.T) {
	for name, body := range map[string]string{
		"empty object":   `{}`,
		"empty serial":   `{"serial":""}`,
		"name only":      `{"name":"rack-3"}`,
		"empty envelope": `{"device":{}}`,
		"model only":     `{"device":{"model":"m"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeCreateRequest(strings.NewReader(body))

			assert.Nil(t, got)
			assert.Equal(t, ErrDeviceSerialRequired{}, err)
		})
	}
}

func TestDecodeCreateRequest_ReportsTheBodyBeforeTheSerial(t *testing.T) {
	_, err := DecodeCreateRequest(strings.NewReader(`{`))
	assert.ErrorAs(t, err, &ErrDeviceRequestBody{})

	_, err = DecodeCreateRequest(strings.NewReader(`{"serial":"A","device":{"serial":"B"}}`))
	assert.Equal(t, ErrDeviceRequestConflict{Field: "serial"}, err)
}

func TestPick(t *testing.T) {
	m := &fieldMerge{}
	assert.Equal(t, "flat", pick(m, "f", "flat", ""))
	assert.Equal(t, "env", pick(m, "f", "", "env"))
	assert.Equal(t, "same", pick(m, "f", "same", "same"))
	assert.Equal(t, "", pick(m, "f", "", ""))
	require.NoError(t, m.err)

	assert.Equal(t, uint32(2), pick(m, "n", uint32(1), uint32(2)))
	assert.Equal(t, ErrDeviceRequestConflict{Field: "n"}, m.err)
}

func TestPickBytes(t *testing.T) {
	m := &fieldMerge{}
	assert.Equal(t, []byte("flat"), pickBytes(m, "b", []byte("flat"), nil))
	assert.Equal(t, []byte("env"), pickBytes(m, "b", nil, []byte("env")))
	assert.Equal(t, []byte("same"), pickBytes(m, "b", []byte("same"), []byte("same")))
	assert.Nil(t, pickBytes(m, "b", nil, []byte{}))
	require.NoError(t, m.err)

	pickBytes(m, "b", []byte("one"), []byte("two"))
	assert.Equal(t, ErrDeviceRequestConflict{Field: "b"}, m.err)
}

func TestRequestErrors(t *testing.T) {
	cause := errors.New("unexpected EOF")
	bodyErr := ErrDeviceRequestBody{Cause: cause}

	assert.Equal(t, "device serial is required", ErrDeviceSerialRequired{}.Error())
	assert.Equal(t,
		`device request sets "serial" flat and in the device envelope to different values`,
		ErrDeviceRequestConflict{Field: "serial"}.Error())
	assert.Equal(t, "invalid device request body: unexpected EOF", bodyErr.Error())
	assert.ErrorIs(t, bodyErr, cause)
}

func TestRequest_DecodesFromTheGoSDKEnvelope(t *testing.T) {
	// The SDK REST transport marshals the proto request, so the envelope keys
	// are the proto JSON names this type declares.
	var req Request
	require.NoError(t, json.Unmarshal([]byte(`{"device":{"serial":"SN-1","attest_cert":"c"}}`), &req))

	got, err := req.ToDevice()
	require.NoError(t, err)
	assert.Equal(t, &entities.Device{Serial: "SN-1", AttestCert: "c"}, got)
}
