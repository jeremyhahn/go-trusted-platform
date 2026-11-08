// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// servedAdmittedVTEP is the record the platformd REST handler writes. The
// wire is pinned to the server's type on the server side
// (pkg/api/rest: TestAdmittedVTEPRoutes_ServeTheSDK).
const servedAdmittedVTEP = `{"vtep":"%s","device_id":42,"host_id":"host-42","serial":"SN42","hostname":"edge-42","allocation_id":"alloc-42","baseline_source":"signed","profile_id":9,"verdict_at":"2026-10-09T12:00:00Z"}`

func wantAdmittedVTEP(vtep string) *platformv1.GatewayAdmittedVTEP {
	return &platformv1.GatewayAdmittedVTEP{
		Vtep: vtep, DeviceId: 42, HostId: "host-42", Serial: "SN42", Hostname: "edge-42",
		AllocationId: "alloc-42", BaselineSource: "signed", ProfileId: 9,
		VerdictAt: timestamppb.New(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)),
	}
}

// sdkGatewayOverREST is the SDK gateway client a CLI caller gets for
// --protocol rest, against a server that records the request URL and
// answers GETs with body.
func sdkGatewayOverREST(t *testing.T, body string) (*sdkgateway.Client, *url.URL) {
	t.Helper()
	requested := &url.URL{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		*requested = *r.URL
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	return sdkgateway.NewClientFromGRPC(platformv1.NewGatewayServiceClient(a.Connection())), requested
}

// The SDK's admitted-VTEP reads used to fall back to a POST on a path no
// server registers. The single-VTEP route also answers the bare record, so a
// generic decode into the reply would have dropped every field.
func TestGatewayAdmittedVTEP_SDKOverREST(t *testing.T) {
	client, requested := sdkGatewayOverREST(t, fmt.Sprintf(servedAdmittedVTEP, "2001:db8::10"))

	got, err := client.GetAdmittedVTEP(context.Background(), "edge-01", "2001:db8::10")
	if err != nil {
		t.Fatalf("GetAdmittedVTEP: %v", err)
	}
	if requested.Path != "/api/v1/sdn/gateway/overlay/vteps/2001:db8::10" || requested.Query().Get("gateway_id") != "edge-01" {
		t.Fatalf("requested %s, want the admitted-VTEP route for edge-01", requested)
	}
	if !proto.Equal(got, wantAdmittedVTEP("2001:db8::10")) {
		t.Fatalf("reply = %v, want %v", got, wantAdmittedVTEP("2001:db8::10"))
	}
}

func TestListGatewayAdmittedVTEPs_SDKOverREST(t *testing.T) {
	client, requested := sdkGatewayOverREST(t, `{"vteps":[`+fmt.Sprintf(servedAdmittedVTEP, "198.51.100.10")+
		`,{"vtep":"198.51.100.11"}],"count":2,"timestamp":"2026-10-09T12:00:05Z"}`)

	got, err := client.ListAdmittedVTEPs(context.Background(), "")
	if err != nil {
		t.Fatalf("ListAdmittedVTEPs: %v", err)
	}
	if requested.Path != "/api/v1/sdn/gateway/overlay/vteps" || requested.RawQuery != "" {
		t.Fatalf("requested %s, want the list route with no gateway filter", requested)
	}
	if len(got) != 2 || !proto.Equal(got[0], wantAdmittedVTEP("198.51.100.10")) || got[1].GetVerdictAt() != nil {
		t.Fatalf("reply = %v", got)
	}
}

func TestGatewayAdmittedVTEP_RESTRefusesAReplyOfAnotherType(t *testing.T) {
	err := decodeGatewayAdmittedVTEP([]byte(`{"vtep":"198.51.100.10"}`), &platformv1.ListGatewayAdmittedVTEPsResponse{})
	var typed ErrUnexpectedReplyType
	if !errors.As(err, &typed) {
		t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
	}
}
