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

package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// TestDecodeSecretValue_RoundTripsJSONEncodedBytes stores bytes the way the
// quicbaas Secrets client does (a JSON-encoded data map) and checks the get
// side returns the stored bytes, not their base64 text.
func TestDecodeSecretValue_RoundTripsJSONEncodedBytes(t *testing.T) {
	stored := []byte{0, 1, 2, 255, 's', 'e', 'k'}
	raw, err := json.Marshal(map[string]interface{}{"value": stored})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := DecodeSecretValue(data["value"])
	if err != nil {
		t.Fatalf("DecodeSecretValue: %v", err)
	}
	if string(got) != string(stored) {
		t.Fatalf("value = %q, want %q", got, stored)
	}
}

func TestDecodeSecretValue_BytesAndNil(t *testing.T) {
	got, err := DecodeSecretValue([]byte("raw"))
	if err != nil || string(got) != "raw" {
		t.Fatalf("[]byte: got %q, %v; want raw, nil", got, err)
	}
	got, err = DecodeSecretValue(nil)
	if err != nil || got != nil {
		t.Fatalf("nil: got %q, %v; want nil, nil", got, err)
	}
}

func TestDecodeSecretValue_MalformedString(t *testing.T) {
	_, err := DecodeSecretValue("not base64!")
	var malformed ErrMalformedSecretValue
	if !errors.As(err, &malformed) {
		t.Fatalf("err = %v, want ErrMalformedSecretValue", err)
	}
	var corrupt base64.CorruptInputError
	if !errors.As(err, &corrupt) {
		t.Fatalf("err = %v, want the base64 cause wrapped", err)
	}
}

func TestDecodeSecretValue_UnexpectedType(t *testing.T) {
	_, err := DecodeSecretValue(float64(42))
	var malformed ErrMalformedSecretValue
	if !errors.As(err, &malformed) || malformed.Type != "float64" {
		t.Fatalf("err = %v, want ErrMalformedSecretValue{Type: float64}", err)
	}
	if malformed.Error() != "stored secret value has unexpected type float64" {
		t.Fatalf("message = %q", malformed.Error())
	}
}

// TestEncodeSecretData_GetReadsTheValueBack encodes a data map for a rotation
// and decodes it the way a get does after the client's JSON round-trip.
func TestEncodeSecretData_GetReadsTheValueBack(t *testing.T) {
	stored := []byte{0, 1, 2, 255, 'n', 'e', 'w'}
	raw, err := EncodeSecretData(map[string]interface{}{"value": stored})
	if err != nil {
		t.Fatalf("EncodeSecretData: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("encoded data is not a JSON map: %v", err)
	}

	got, err := DecodeSecretValue(data["value"])
	if err != nil {
		t.Fatalf("DecodeSecretValue: %v", err)
	}
	if string(got) != string(stored) {
		t.Fatalf("value = %q, want %q", got, stored)
	}
}

func TestEncodeSecretData_UnencodableValueIsTyped(t *testing.T) {
	_, err := EncodeSecretData(map[string]interface{}{"value": make(chan int)})
	var encErr ErrSecretDataEncoding
	if !errors.As(err, &encErr) {
		t.Fatalf("error = %v, want ErrSecretDataEncoding", err)
	}
}

func TestDecodeSecretData_InvertsEncodeSecretData(t *testing.T) {
	raw, err := EncodeSecretData(map[string]interface{}{"value": []byte("s3cret"), "description": "db"})
	if err != nil {
		t.Fatalf("EncodeSecretData: %v", err)
	}
	data, err := DecodeSecretData(raw)
	if err != nil {
		t.Fatalf("DecodeSecretData: %v", err)
	}
	value, err := DecodeSecretValue(data["value"])
	if err != nil {
		t.Fatalf("DecodeSecretValue: %v", err)
	}
	if string(value) != "s3cret" || data["description"] != "db" {
		t.Fatalf("decoded value %q, description %v; want s3cret, db", value, data["description"])
	}
}

func TestDecodeSecretData_MalformedDataIsTyped(t *testing.T) {
	_, err := DecodeSecretData([]byte("s3cret"))
	var decErr ErrSecretDataDecoding
	if !errors.As(err, &decErr) {
		t.Fatalf("error = %v, want ErrSecretDataDecoding", err)
	}
}
