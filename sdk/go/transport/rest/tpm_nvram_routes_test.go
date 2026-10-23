// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// nvCall is what the fake server saw of one NV request.
type nvCall struct {
	method string
	path   string
	body   map[string]any
}

// tpmNVServer answers every NV request with body and records the call.
func tpmNVServer(t *testing.T, body string, call *nvCall) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		call.method, call.path = r.Method, r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &call.body); err != nil {
				t.Errorf("decode request body: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	return a
}

// TestTPMNVRAMRoutes_IndexTravelsInThePath pins the NV index to the path the
// server registers (/api/v1/tpm/nvram/{index}) and the remaining fields to
// the body; the index-less /api/v1/tpm/nvram the SDK used to call has no
// read, write or undefine handler (#452).
func TestTPMNVRAMRoutes_IndexTravelsInThePath(t *testing.T) {
	const index = 0x01C00002
	const wantPath = "/api/v1/tpm/nvram/29360130"

	t.Run("ReadNVRAM", func(t *testing.T) {
		var call nvCall
		a := tpmNVServer(t, envelope(`{"data":"bnY="}`), &call)

		reply := &platformv1.ReadNVRAMResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_ReadNVRAM_FullMethodName,
			&platformv1.ReadNVRAMRequest{Index: index, Password: "pw", Size: 16}, reply); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if call.method != http.MethodGet || call.path != wantPath {
			t.Errorf("request = %s %s, want GET %s", call.method, call.path, wantPath)
		}
		if _, ok := call.body["index"]; ok {
			t.Errorf("body carries the index: %v", call.body)
		}
		if call.body["password"] != "pw" || call.body["size"] != float64(16) {
			t.Errorf("body = %v, want password and size", call.body)
		}
		if string(reply.GetData()) != "nv" {
			t.Errorf("data = %q, want the decoded nv", reply.GetData())
		}
	})

	t.Run("WriteNVRAM", func(t *testing.T) {
		var call nvCall
		a := tpmNVServer(t, envelope(`{}`), &call)

		if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_WriteNVRAM_FullMethodName,
			&platformv1.WriteNVRAMRequest{Index: index, Data: []byte("payload")},
			&platformv1.WriteNVRAMResponse{}); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if call.method != http.MethodPut || call.path != wantPath {
			t.Errorf("request = %s %s, want PUT %s", call.method, call.path, wantPath)
		}
		if _, ok := call.body["index"]; ok {
			t.Errorf("body carries the index: %v", call.body)
		}
		if call.body["data"] != "cGF5bG9hZA==" {
			t.Errorf("body data = %v, want base64 payload", call.body["data"])
		}
	})

	t.Run("UndefineNVRAM", func(t *testing.T) {
		var call nvCall
		a := tpmNVServer(t, envelope(`{}`), &call)

		if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_UndefineNVRAM_FullMethodName,
			&platformv1.UndefineNVRAMRequest{Index: index, Password: "pw"},
			&platformv1.UndefineNVRAMResponse{}); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if call.method != http.MethodDelete || call.path != wantPath {
			t.Errorf("request = %s %s, want DELETE %s", call.method, call.path, wantPath)
		}
		if call.body["password"] != "pw" {
			t.Errorf("body = %v, want the password", call.body)
		}
	})
}

// TestTPMNVRAMRoutes_ZeroIndexIsRefusedLocally: index 0 is not an NV index
// and would leave the path without one, so the adapter refuses it before
// sending anything.
func TestTPMNVRAMRoutes_ZeroIndexIsRefusedLocally(t *testing.T) {
	var call nvCall
	a := tpmNVServer(t, envelope(`{}`), &call)

	err := a.Connection().Invoke(context.Background(), platformv1.TPMService_ReadNVRAM_FullMethodName,
		&platformv1.ReadNVRAMRequest{}, &platformv1.ReadNVRAMResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Invoke error = %v, want InvalidArgument", err)
	}
	if call.path != "" {
		t.Errorf("request reached the server: %s %s", call.method, call.path)
	}
}
