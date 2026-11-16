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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// registryReadsCall is one request the capture server saw.
type registryReadsCall struct {
	method  string
	rawPath string
	query   string
}

// registryReadsAdapter connects an adapter to a TLS capture server that
// records every request and answers each with body.
func registryReadsAdapter(t *testing.T, body func(r *http.Request) string) (*Adapter, func() []registryReadsCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []registryReadsCall
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			mu.Lock()
			calls = append(calls, registryReadsCall{method: r.Method, rawPath: r.URL.EscapedPath(), query: r.URL.RawQuery})
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body(r)))
	}))
	t.Cleanup(server.Close)

	a, err := Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer(server)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter), func() []registryReadsCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]registryReadsCall(nil), calls...)
	}
}

func registryReadsEnvelope(payload string) string {
	return `{"code":200,"success":true,"payload":` + payload + `}`
}

func TestRegistryReads_ResolveToTheServedRoutes(t *testing.T) {
	a, seen := registryReadsAdapter(t, func(*http.Request) string { return registryReadsEnvelope(`{}`) })
	conn := a.Connection()
	ctx := context.Background()

	if err := conn.Invoke(ctx, platformv1.RegistryService_List_FullMethodName,
		&platformv1.ListArtifactsRequest{Repository: "team/app", Limit: 5, Offset: 10},
		&platformv1.ListArtifactsResponse{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Status_FullMethodName,
		&platformv1.RegistryStatusRequest{}, &platformv1.RegistryStatusResponse{}); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Inspect_FullMethodName,
		&platformv1.InspectArtifactRequest{Repository: "team/app", Reference: "v1"},
		&platformv1.InspectArtifactResponse{}); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	want := []registryReadsCall{
		{method: http.MethodGet, rawPath: "/api/v1/compute/images", query: "limit=5&offset=10&repository=team%2Fapp"},
		{method: http.MethodGet, rawPath: "/api/v1/compute/images/status"},
		{method: http.MethodGet, rawPath: "/api/v1/compute/images/team%2Fapp:v1"},
	}
	got := seen()
	if len(got) != len(want) {
		t.Fatalf("calls = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRegistryReads_EmptyRefNeverReachesTheWire(t *testing.T) {
	a, seen := registryReadsAdapter(t, func(*http.Request) string { return registryReadsEnvelope(`{}`) })
	conn := a.Connection()

	for name, req := range map[string]*platformv1.InspectArtifactRequest{
		"empty repository": {Reference: "v1"},
		"empty reference":  {Repository: "team/app"},
	} {
		err := conn.Invoke(context.Background(), platformv1.RegistryService_Inspect_FullMethodName,
			req, &platformv1.InspectArtifactResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v (%v), want InvalidArgument", name, status.Code(err), err)
		}
	}
	if calls := seen(); len(calls) != 0 {
		t.Errorf("server saw %+v, want no request", calls)
	}
}

func TestRegistryReads_DecodeTheServedReplies(t *testing.T) {
	const listBody = `{"images":[{"repository":"team/app","tag":"v1","digest":"sha256:aa","media_type":"m","size":42,"layers":2,` +
		`"annotations":{"k":"v"},"created_at":"2025-01-02T03:04:05Z","updated_at":"2025-01-03T03:04:05Z"}],"total":7}`
	const statusBody = `{"Health":2,"Version":"1.2.3","Storage":{"TotalBytes":100,"UsedBytes":40,"AvailableBytes":60,` +
		`"ArtifactCount":3,"LayerCount":4,"RepositoryCount":1},"ReadOnly":true,"Components":[{"Name":"store","Status":1,` +
		`"Message":"ok","LastCheck":"2025-01-02T03:04:05Z","Details":{"a":"b"}}],` +
		`"StartedAt":"2025-01-01T00:00:00Z","Timestamp":"2025-01-02T00:00:00Z"}`
	const inspectBody = `{"Artifact":{"ID":"id1","Repository":"team/app","Tag":"v1","Digest":"sha256:bb","Type":1,"State":2,` +
		`"Size":9,"Manifest":null,"Labels":{"l":"1"},"Annotations":null,"OS":"linux","Architecture":"amd64","Author":"me",` +
		`"CreatedAt":"2025-01-02T03:04:05Z","UpdatedAt":"0001-01-01T00:00:00Z","PushedAt":"0001-01-01T00:00:00Z",` +
		`"LastPulledAt":"0001-01-01T00:00:00Z","PullCount":3},"Signatures":null,"ScanResult":null,"Tags":["v1","latest"]}`

	a, _ := registryReadsAdapter(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/api/v1/compute/images":
			return registryReadsEnvelope(listBody)
		case "/api/v1/compute/images/status":
			return registryReadsEnvelope(statusBody)
		default:
			return registryReadsEnvelope(inspectBody)
		}
	})
	conn := a.Connection()
	ctx := context.Background()

	list := &platformv1.ListArtifactsResponse{}
	if err := conn.Invoke(ctx, platformv1.RegistryService_List_FullMethodName, &platformv1.ListArtifactsRequest{}, list); err != nil {
		t.Fatalf("List: %v", err)
	}
	if list.GetTotal() != 7 || len(list.GetArtifacts()) != 1 {
		t.Fatalf("list = %v", list)
	}
	art := list.GetArtifacts()[0]
	if art.GetRepository() != "team/app" || art.GetTag() != "v1" || art.GetDigest() != "sha256:aa" ||
		art.GetSize() != 42 || art.GetAnnotations()["k"] != "v" {
		t.Errorf("list artifact = %v", art)
	}
	if !art.GetCreatedAt().AsTime().Equal(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("created_at = %v", art.GetCreatedAt())
	}

	st := &platformv1.RegistryStatusResponse{}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Status_FullMethodName, &platformv1.RegistryStatusRequest{}, st); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetHealth() != platformv1.HealthStatus_HEALTH_STATUS_DEGRADED || st.GetVersion() != "1.2.3" || !st.GetReadOnly() {
		t.Errorf("status = %v", st)
	}
	if st.GetStorage().GetUsedBytes() != 40 || st.GetStorage().GetRepositoryCount() != 1 {
		t.Errorf("storage = %v", st.GetStorage())
	}
	if len(st.GetComponents()) != 1 || st.GetComponents()[0].GetStatus() != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY ||
		st.GetComponents()[0].GetName() != "store" {
		t.Errorf("components = %v", st.GetComponents())
	}
	if !st.GetStartedAt().AsTime().Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("started_at = %v", st.GetStartedAt())
	}

	in := &platformv1.InspectArtifactResponse{}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Inspect_FullMethodName,
		&platformv1.InspectArtifactRequest{Repository: "team/app", Reference: "v1"}, in); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	da := in.GetDetail().GetArtifact()
	if da.GetDigest() != "sha256:bb" || da.GetId() != "id1" || da.GetOs() != "linux" || da.GetPullCount() != 3 ||
		da.GetType() != platformv1.ArtifactType(1) || da.GetState() != platformv1.ArtifactState(2) {
		t.Errorf("inspect artifact = %v", da)
	}
	if da.GetUpdatedAt() != nil {
		t.Errorf("zero updated_at decoded as %v, want unset", da.GetUpdatedAt())
	}
	if tags := in.GetDetail().GetTags(); len(tags) != 2 || tags[1] != "latest" {
		t.Errorf("tags = %v", tags)
	}
}
