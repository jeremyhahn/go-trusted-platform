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

package restwire

import (
	"encoding/json"
	"testing"
)

// TestWebServiceResponse_JSONFieldNames pins the envelope's wire names; a
// renamed tag would break every REST client.
func TestWebServiceResponse_JSONFieldNames(t *testing.T) {
	data, err := json.Marshal(WebServiceResponse{
		Code:    200,
		Success: true,
		Payload: map[string]string{"key": "value"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"code":200,"error":"","success":true,"payload":{"key":"value"}}`
	if string(data) != want {
		t.Errorf("envelope = %s, want %s", data, want)
	}
}

func TestWebServiceResponse_DecodesErrorEnvelope(t *testing.T) {
	var resp WebServiceResponse
	err := json.Unmarshal([]byte(`{"code":500,"error":"internal error","success":false,"payload":null}`), &resp)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Code != 500 || resp.Success || resp.Error != "internal error" || resp.Payload != nil {
		t.Errorf("decoded = %+v, want the 500 error envelope", resp)
	}
}

func TestWebServiceResponse_RejectsMalformedEnvelope(t *testing.T) {
	var resp WebServiceResponse
	if err := json.Unmarshal([]byte(`{"code":"not-a-number"}`), &resp); err == nil {
		t.Error("Unmarshal accepted a string code, want a type error")
	}
}
