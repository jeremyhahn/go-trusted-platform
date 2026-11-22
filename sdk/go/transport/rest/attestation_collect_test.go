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
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// collectCapture records the one API request the collect routes send.
type collectCapture struct {
	calls  int
	method string
	path   string
	body   []byte
}

// collectAdapter serves the given envelope for every API request and
// records the request it received.
func collectAdapter(t *testing.T, body string, captured *collectCapture) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.calls++
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	return a
}

func TestAttestationCollect_ResolveToTheServedRoutes(t *testing.T) {
	t.Run("vm", func(t *testing.T) {
		var captured collectCapture
		a := collectAdapter(t,
			`{"code":200,"success":true,"payload":{"attestation":{"vmId":"vm-1"}}}`, &captured)

		resp := &platformv1.CollectVMAttestationResponse{}
		err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_CollectVMAttestation_FullMethodName,
			&platformv1.CollectVMAttestationRequest{VmId: "vm-1", Nonce: []byte{1, 2, 3}}, resp)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodPost || captured.path != "/api/v1/attestation/vm/vm-1" {
			t.Errorf("request = %s %s, want POST /api/v1/attestation/vm/vm-1", captured.method, captured.path)
		}
		sent := &platformv1.CollectVMAttestationRequest{}
		if err := protojson.Unmarshal(captured.body, sent); err != nil {
			t.Fatalf("body %q is not a CollectVMAttestationRequest: %v", captured.body, err)
		}
		if string(sent.GetNonce()) != string([]byte{1, 2, 3}) {
			t.Errorf("body nonce = %v, want [1 2 3]", sent.GetNonce())
		}
		if resp.GetAttestation().GetVmId() != "vm-1" {
			t.Errorf("resp = %+v, want the attestation of vm-1", resp)
		}
	})

	t.Run("container", func(t *testing.T) {
		var captured collectCapture
		a := collectAdapter(t,
			`{"code":200,"success":true,"payload":{"attestation":{"containerId":"ctr-1"}}}`, &captured)

		resp := &platformv1.CollectContainerAttestationResponse{}
		err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_CollectContainerAttestation_FullMethodName,
			&platformv1.CollectContainerAttestationRequest{ContainerId: "ctr-1"}, resp)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodPost || captured.path != "/api/v1/attestation/container/ctr-1" {
			t.Errorf("request = %s %s, want POST /api/v1/attestation/container/ctr-1", captured.method, captured.path)
		}
		if resp.GetAttestation().GetContainerId() != "ctr-1" {
			t.Errorf("resp = %+v, want the attestation of ctr-1", resp)
		}
	})
}

func TestAttestationCollect_EmptyIDNeverReachesTheWire(t *testing.T) {
	var captured collectCapture
	a := collectAdapter(t, `{"code":200,"success":true,"payload":{}}`, &captured)

	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_CollectVMAttestation_FullMethodName,
		&platformv1.CollectVMAttestationRequest{Nonce: []byte{1}}, &platformv1.CollectVMAttestationResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("CollectVMAttestation with no vm_id: code = %v (%v), want InvalidArgument", status.Code(err), err)
	}

	err = a.Connection().Invoke(context.Background(), platformv1.AttestationService_CollectContainerAttestation_FullMethodName,
		&platformv1.CollectContainerAttestationRequest{}, &platformv1.CollectContainerAttestationResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("CollectContainerAttestation with no container_id: code = %v (%v), want InvalidArgument", status.Code(err), err)
	}

	if captured.calls != 0 {
		t.Errorf("server saw %d API requests, want none (last %s %s)", captured.calls, captured.method, captured.path)
	}
}
