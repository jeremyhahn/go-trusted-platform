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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeComputeService records the request and context of the last RPC and
// answers with resp, or with err when it is set.
type fakeComputeService struct {
	platformv1.UnimplementedComputeServiceServer

	resp proto.Message
	err  error

	ctx context.Context
	req proto.Message
}

func computeAnswer[Resp proto.Message](f *fakeComputeService, ctx context.Context, req proto.Message, empty Resp) (Resp, error) {
	f.ctx, f.req = ctx, req
	if f.err != nil {
		var none Resp
		return none, f.err
	}
	if resp, ok := f.resp.(Resp); ok {
		return resp, nil
	}
	return empty, nil
}

func (f *fakeComputeService) CreateVM(ctx context.Context, req *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.CreateVMResponse{})
}

func (f *fakeComputeService) ListVMs(ctx context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ListVMsResponse{})
}

func (f *fakeComputeService) GetVM(ctx context.Context, req *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.GetVMResponse{})
}

func (f *fakeComputeService) DeleteVM(ctx context.Context, req *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.DeleteVMResponse{})
}

func (f *fakeComputeService) StartVM(ctx context.Context, req *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.StartVMResponse{})
}

func (f *fakeComputeService) StopVM(ctx context.Context, req *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.StopVMResponse{})
}

func (f *fakeComputeService) RebootVM(ctx context.Context, req *platformv1.RebootVMRequest) (*platformv1.RebootVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.RebootVMResponse{})
}

func (f *fakeComputeService) SuspendVM(ctx context.Context, req *platformv1.SuspendVMRequest) (*platformv1.SuspendVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.SuspendVMResponse{})
}

func (f *fakeComputeService) ResumeVM(ctx context.Context, req *platformv1.ResumeVMRequest) (*platformv1.ResumeVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ResumeVMResponse{})
}

func (f *fakeComputeService) GetVMMetrics(ctx context.Context, req *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.VMMetricsResponse{})
}

func (f *fakeComputeService) MigrateVM(ctx context.Context, req *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.MigrateVMResponse{})
}

func (f *fakeComputeService) AttachDisk(ctx context.Context, req *platformv1.AttachDiskRequest) (*platformv1.AttachDiskResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.AttachDiskResponse{})
}

func (f *fakeComputeService) DetachDisk(ctx context.Context, req *platformv1.DetachDiskRequest) (*platformv1.DetachDiskResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.DetachDiskResponse{})
}

func (f *fakeComputeService) ResizeDisk(ctx context.Context, req *platformv1.ResizeDiskRequest) (*platformv1.ResizeDiskResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ResizeDiskResponse{})
}

func (f *fakeComputeService) CreateSnapshot(ctx context.Context, req *platformv1.CreateSnapshotRequest) (*platformv1.CreateSnapshotResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.CreateSnapshotResponse{})
}

func (f *fakeComputeService) ListSnapshots(ctx context.Context, req *platformv1.ListSnapshotsRequest) (*platformv1.ListSnapshotsResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ListSnapshotsResponse{})
}

func (f *fakeComputeService) DeleteSnapshot(ctx context.Context, req *platformv1.DeleteSnapshotRequest) (*platformv1.DeleteSnapshotResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.DeleteSnapshotResponse{})
}

func (f *fakeComputeService) RestoreSnapshot(ctx context.Context, req *platformv1.RestoreSnapshotRequest) (*platformv1.RestoreSnapshotResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.RestoreSnapshotResponse{})
}

func (f *fakeComputeService) AttestVM(ctx context.Context, req *platformv1.AttestVMRequest) (*platformv1.AttestVMResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.AttestVMResponse{})
}

func (f *fakeComputeService) VerifyVMAttestation(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (*platformv1.VerifyVMAttestationResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.VerifyVMAttestationResponse{})
}

func (f *fakeComputeService) CreateContainer(ctx context.Context, req *platformv1.CreateContainerRequest) (*platformv1.CreateContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.CreateContainerResponse{})
}

func (f *fakeComputeService) ListContainers(ctx context.Context, req *platformv1.ListContainersRequest) (*platformv1.ListContainersResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ListContainersResponse{})
}

func (f *fakeComputeService) GetContainer(ctx context.Context, req *platformv1.GetContainerRequest) (*platformv1.GetContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.GetContainerResponse{})
}

func (f *fakeComputeService) DeleteContainer(ctx context.Context, req *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.DeleteContainerResponse{})
}

func (f *fakeComputeService) StartContainer(ctx context.Context, req *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.StartContainerResponse{})
}

func (f *fakeComputeService) StopContainer(ctx context.Context, req *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.StopContainerResponse{})
}

func (f *fakeComputeService) ExecContainer(ctx context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ExecContainerResponse{})
}

func (f *fakeComputeService) AttestContainer(ctx context.Context, req *platformv1.AttestContainerRequest) (*platformv1.AttestContainerResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.AttestContainerResponse{})
}

func (f *fakeComputeService) GetContainerMetrics(ctx context.Context, req *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	return computeAnswer(f, ctx, req, &platformv1.ContainerMetricsResponse{})
}

// computeRouter mounts the compute routes over compute behind a guard that
// admits operatorToken.
func computeRouter(compute platformv1.ComputeServiceServer) *mux.Router {
	router := mux.NewRouter()
	NewComputeHandlers(compute, operatorGuard(), nil).RegisterRoutes(router)
	return router
}

// serveCompute sends one operator request with body (if any) to router.
func serveCompute(router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, operatorRequest(method, target, strings.NewReader(body)))
	return rec
}

type computeRouteCase struct {
	route  string // the mounted method and path template
	method string
	target string
	body   string        // the camelCase protojson body, if any
	want   proto.Message // the request the compute service must receive
	resp   proto.Message // what the compute service answers
	key    string        // a camelCase key the response must carry
}

// computeRouteCases is one SDK-shaped request per mounted compute route.
func computeRouteCases() []computeRouteCase {
	ok := &platformv1.Status{Success: true, Message: "done"}
	sha256 := platformv1.PCRBank_PCR_BANK_SHA256
	vms := computeBasePath + "/vms"
	containers := computeBasePath + "/containers"
	return []computeRouteCase{
		{
			route: "POST " + vms, method: http.MethodPost, target: vms,
			body: `{"config":{"name":"web","secureBoot":true,"labels":{"env":"prod"}},"start":true}`,
			want: &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "web", SecureBoot: true, Labels: map[string]string{"env": "prod"}}, Start: true},
			resp: &platformv1.CreateVMResponse{Status: ok, Vm: &platformv1.VM{Id: "vm-1", HostId: "host-1"}}, key: "vm",
		},
		{
			route: "GET " + vms, method: http.MethodGet,
			target: vms + "?states=VM_STATE_RUNNING&states=VM_STATE_STOPPED&pagination.page=2&pagination.pageSize=10&selector.matchLabels.env=prod",
			want: &platformv1.ListVMsRequest{
				Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10},
				States:     []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, platformv1.VMState_VM_STATE_STOPPED},
			},
			resp: &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1", HostId: "host-1"}}}, key: "vms",
		},
		{
			route: "GET " + vms + "/{id}", method: http.MethodGet, target: vms + "/vm-1",
			want: &platformv1.GetVMRequest{Id: "vm-1"},
			resp: &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "vm-1", HostId: "host-1"}}, key: "vm",
		},
		{
			route: "DELETE " + vms + "/{id}", method: http.MethodDelete, target: vms + "/vm-1?deleteDisks=true",
			want: &platformv1.DeleteVMRequest{Id: "vm-1", DeleteDisks: true},
			resp: &platformv1.DeleteVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{id}/start", method: http.MethodPost, target: vms + "/vm-1/start", body: `{}`,
			want: &platformv1.StartVMRequest{Id: "vm-1"},
			resp: &platformv1.StartVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{id}/stop", method: http.MethodPost, target: vms + "/vm-1/stop",
			body: `{"force":true,"timeoutSeconds":30}`,
			want: &platformv1.StopVMRequest{Id: "vm-1", Force: true, TimeoutSeconds: 30},
			resp: &platformv1.StopVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{id}/reboot", method: http.MethodPost, target: vms + "/vm-1/reboot", body: `{"force":true}`,
			want: &platformv1.RebootVMRequest{Id: "vm-1", Force: true},
			resp: &platformv1.RebootVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{id}/suspend", method: http.MethodPost, target: vms + "/vm-1/suspend", body: `{}`,
			want: &platformv1.SuspendVMRequest{Id: "vm-1"},
			resp: &platformv1.SuspendVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{id}/resume", method: http.MethodPost, target: vms + "/vm-1/resume",
			want: &platformv1.ResumeVMRequest{Id: "vm-1"},
			resp: &platformv1.ResumeVMResponse{Status: ok}, key: "status",
		},
		{
			route: "GET " + vms + "/{id}/metrics", method: http.MethodGet, target: vms + "/vm-1/metrics",
			want: &platformv1.GetVMMetricsRequest{Id: "vm-1"},
			resp: &platformv1.VMMetricsResponse{Metrics: &platformv1.VMMetrics{UptimeSeconds: 60, MemoryUsedMb: 512}}, key: "metrics",
		},
		{
			route: "POST " + vms + "/{vmId}/migrate", method: http.MethodPost, target: vms + "/vm-1/migrate",
			body: `{"destinationHost":"node-2","liveMigration":true,"bandwidthLimitMbps":100}`,
			want: &platformv1.MigrateVMRequest{VmId: "vm-1", DestinationHost: "node-2", LiveMigration: true, BandwidthLimitMbps: 100},
			resp: &platformv1.MigrateVMResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{vmId}/disks", method: http.MethodPost, target: vms + "/vm-1/disks",
			body: `{"disk":{"id":"disk-1","sizeGb":20,"readonly":true}}`,
			want: &platformv1.AttachDiskRequest{VmId: "vm-1", Disk: &platformv1.DiskConfig{Id: "disk-1", SizeGb: 20, Readonly: true}},
			resp: &platformv1.AttachDiskResponse{Status: ok}, key: "status",
		},
		{
			route: "DELETE " + vms + "/{vmId}/disks/{diskId}", method: http.MethodDelete, target: vms + "/vm-1/disks/disk-1",
			want: &platformv1.DetachDiskRequest{VmId: "vm-1", DiskId: "disk-1"},
			resp: &platformv1.DetachDiskResponse{Status: ok}, key: "status",
		},
		{
			route: "PATCH " + vms + "/{vmId}/disks/{diskId}", method: http.MethodPatch, target: vms + "/vm-1/disks/disk-1",
			body: `{"newSizeGb":40}`,
			want: &platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "disk-1", NewSizeGb: 40},
			resp: &platformv1.ResizeDiskResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{vmId}/snapshots", method: http.MethodPost, target: vms + "/vm-1/snapshots",
			body: `{"config":{"name":"nightly","memorySnapshot":true}}`,
			want: &platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{Name: "nightly", MemorySnapshot: true}},
			resp: &platformv1.CreateSnapshotResponse{Status: ok, Snapshot: &platformv1.Snapshot{Id: "snap-1", SizeBytes: 1024}}, key: "snapshot",
		},
		{
			route: "GET " + vms + "/{vmId}/snapshots", method: http.MethodGet, target: vms + "/vm-1/snapshots",
			want: &platformv1.ListSnapshotsRequest{VmId: "vm-1"},
			resp: &platformv1.ListSnapshotsResponse{Snapshots: []*platformv1.Snapshot{{Id: "snap-1", VmId: "vm-1"}}}, key: "snapshots",
		},
		{
			route: "DELETE " + vms + "/{vmId}/snapshots/{snapshotId}", method: http.MethodDelete, target: vms + "/vm-1/snapshots/snap-1",
			want: &platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
			resp: &platformv1.DeleteSnapshotResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{vmId}/snapshots/{snapshotId}/restore", method: http.MethodPost, target: vms + "/vm-1/snapshots/snap-1/restore",
			body: `{}`,
			want: &platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
			resp: &platformv1.RestoreSnapshotResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + vms + "/{vmId}/attest", method: http.MethodPost, target: vms + "/vm-1/attest",
			body: `{"nonce":"bm9uY2U=","pcrIndices":[0,7],"pcrBank":"PCR_BANK_SHA256"}`,
			want: &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7}, PcrBank: sha256},
			resp: &platformv1.AttestVMResponse{Quote: []byte("quote"), SignatureAlgorithm: "SHA256-RSAPSS"}, key: "signatureAlgorithm",
		},
		{
			route: "POST " + vms + "/{vmId}/attest/verify", method: http.MethodPost, target: vms + "/vm-1/attest/verify",
			body: `{"vmId":"vm-1","quote":"cXVvdGU=","signatureAlgorithm":"SHA256-RSAPSS","expectedPcrs":[{"index":7,"bank":"PCR_BANK_SHA256","value":"cGNy"}]}`,
			want: &platformv1.VerifyVMAttestationRequest{
				VmId: "vm-1", Quote: []byte("quote"), SignatureAlgorithm: "SHA256-RSAPSS",
				ExpectedPcrs: []*platformv1.PCRValue{{Index: 7, Bank: sha256, Value: []byte("pcr")}},
			},
			resp: &platformv1.VerifyVMAttestationResponse{Verified: true, ActualPcrs: []*platformv1.PCRValue{{Index: 7, Bank: sha256}}}, key: "actualPcrs",
		},
		{
			route: "POST " + containers, method: http.MethodPost, target: containers,
			body: `{"config":{"name":"web","image":"nginx","imageHash":"sha256:abc"},"start":true,"attestOnCreate":true}`,
			want: &platformv1.CreateContainerRequest{Config: &platformv1.ContainerConfig{Name: "web", Image: "nginx", ImageHash: "sha256:abc"}, Start: true, AttestOnCreate: true},
			resp: &platformv1.CreateContainerResponse{Status: ok, Container: &platformv1.Container{Id: "ctr-1", HostId: "host-1"}}, key: "container",
		},
		{
			route: "GET " + containers, method: http.MethodGet,
			target: containers + "?nameFilter=web&states=CONTAINER_STATE_RUNNING&pagination.pageSize=5&selector.matchLabels.tier=edge",
			want: &platformv1.ListContainersRequest{
				Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "edge"}},
				Pagination: &platformv1.PaginationRequest{PageSize: 5},
				States:     []platformv1.ContainerState{platformv1.ContainerState_CONTAINER_STATE_RUNNING},
				NameFilter: "web",
			},
			resp: &platformv1.ListContainersResponse{Containers: []*platformv1.Container{{Id: "ctr-1", ExitCode: 0}}}, key: "containers",
		},
		{
			route: "GET " + containers + "/{id}", method: http.MethodGet, target: containers + "/ctr-1",
			want: &platformv1.GetContainerRequest{Id: "ctr-1"},
			resp: &platformv1.GetContainerResponse{Container: &platformv1.Container{Id: "ctr-1", HostId: "host-1"}}, key: "container",
		},
		{
			route: "DELETE " + containers + "/{id}", method: http.MethodDelete, target: containers + "/ctr-1?force=true&deleteVolumes=true",
			want: &platformv1.DeleteContainerRequest{Id: "ctr-1", Force: true, DeleteVolumes: true},
			resp: &platformv1.DeleteContainerResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + containers + "/{id}/start", method: http.MethodPost, target: containers + "/ctr-1/start", body: `{}`,
			want: &platformv1.StartContainerRequest{Id: "ctr-1"},
			resp: &platformv1.StartContainerResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + containers + "/{id}/stop", method: http.MethodPost, target: containers + "/ctr-1/stop",
			body: `{"timeoutSeconds":5}`,
			want: &platformv1.StopContainerRequest{Id: "ctr-1", TimeoutSeconds: 5},
			resp: &platformv1.StopContainerResponse{Status: ok}, key: "status",
		},
		{
			route: "POST " + containers + "/{id}/exec", method: http.MethodPost, target: containers + "/ctr-1/exec",
			body: `{"id":"ctr-1","command":["ls","-l"],"env":[{"name":"A","value":"1"}],"workingDir":"/tmp","tty":true}`,
			want: &platformv1.ExecContainerRequest{
				Id: "ctr-1", Command: []string{"ls", "-l"}, Env: []*platformv1.EnvVar{{Name: "A", Value: "1"}},
				WorkingDir: "/tmp", Tty: true,
			},
			resp: &platformv1.ExecContainerResponse{ExitCode: 2, Stdout: []byte("out")}, key: "exitCode",
		},
		{
			route: "POST " + containers + "/{id}/attest", method: http.MethodPost, target: containers + "/ctr-1/attest",
			body: `{"nonce":"bm9uY2U=","pcrBank":"PCR_BANK_SHA256"}`,
			want: &platformv1.AttestContainerRequest{Id: "ctr-1", Nonce: []byte("nonce"), PcrBank: sha256},
			resp: &platformv1.AttestContainerResponse{ContainerId: "ctr-1", AkPublic: []byte("ak")}, key: "akPublic",
		},
		{
			route: "GET " + containers + "/{id}/metrics", method: http.MethodGet, target: containers + "/ctr-1/metrics",
			want: &platformv1.GetContainerMetricsRequest{Id: "ctr-1"},
			resp: &platformv1.ContainerMetricsResponse{Metrics: &platformv1.ContainerMetrics{MemoryLimitMb: 512}}, key: "metrics",
		},
	}
}

func TestComputeRoutesServeTheSDKContract(t *testing.T) {
	cases := computeRouteCases()

	mounted := map[string]bool{}
	for _, route := range NewComputeHandlers(nil, nil, nil).routes() {
		mounted[route.method+" "+computeBasePath+route.path] = true
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.route] = true
	}
	require.Equal(t, mounted, covered, "every mounted compute route needs exactly one case")
	require.Len(t, computeRouteScopes, len(mounted), "every mounted compute route needs a scope case")

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			compute := &fakeComputeService{resp: tc.resp}

			rec := serveCompute(computeRouter(compute), tc.method, tc.target, tc.body)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			require.NotNil(t, compute.req, "the compute service must be called")
			assert.True(t, proto.Equal(tc.want, compute.req), "want %v, got %v", tc.want, compute.req)

			var keys map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keys), rec.Body.String())
			assert.Contains(t, keys, tc.key, rec.Body.String())

			got := tc.resp.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), got))
			assert.True(t, proto.Equal(tc.resp, got), "want %v, got %v", tc.resp, got)
		})
	}
}

func TestComputeRoutesAcceptProtoNames(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		body   string
		want   proto.Message
	}{
		{
			"a body in proto names", http.MethodPost, computeBasePath + "/vms/vm-1/migrate",
			`{"destination_host":"node-2","live_migration":true}`,
			&platformv1.MigrateVMRequest{VmId: "vm-1", DestinationHost: "node-2", LiveMigration: true},
		},
		{
			"query parameters in proto names", http.MethodDelete, computeBasePath + "/containers/ctr-1?delete_volumes=true",
			"", &platformv1.DeleteContainerRequest{Id: "ctr-1", DeleteVolumes: true},
		},
		{
			"nested query parameters in proto names", http.MethodGet, computeBasePath + "/vms?pagination.page_size=3&selector.match_labels.env=prod",
			"", &platformv1.ListVMsRequest{
				Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				Pagination: &platformv1.PaginationRequest{PageSize: 3},
			},
		},
		{
			"the path ID over a body ID", http.MethodPost, computeBasePath + "/containers/ctr-1/exec",
			`{"id":"ctr-2","command":["true"]}`, &platformv1.ExecContainerRequest{Id: "ctr-1", Command: []string{"true"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compute := &fakeComputeService{}

			rec := serveCompute(computeRouter(compute), tc.method, tc.target, tc.body)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, compute.req), "want %v, got %v", tc.want, compute.req)
		})
	}
}

// TestComputeRoutesRefuseMalformedRequests pins that a request field the
// message does not have is an error on every route, never a silent default,
// and that a refused request never reaches the compute service.
func TestComputeRoutesRefuseMalformedRequests(t *testing.T) {
	for _, tc := range computeRouteCases() {
		t.Run(tc.route+" unknown body field", func(t *testing.T) {
			compute := &fakeComputeService{}

			rec := serveCompute(computeRouter(compute), tc.method, tc.target, `{"notAField":1}`)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, decodeTPMError(t, rec).Error, `unknown field "notAField"`)
			assert.Nil(t, compute.req, "a malformed request must not reach the compute service")
		})

		t.Run(tc.route+" unknown query parameter", func(t *testing.T) {
			compute := &fakeComputeService{}
			separator := "?"
			if strings.Contains(tc.target, "?") {
				separator = "&"
			}

			rec := serveCompute(computeRouter(compute), tc.method, tc.target+separator+"notAField=1", "")

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, decodeTPMError(t, rec).Error, "invalid query parameter notAField")
			assert.Nil(t, compute.req, "a malformed request must not reach the compute service")
		})
	}

	refusals := []struct {
		name   string
		method string
		target string
		body   string
		want   string
	}{
		{"a body that is not JSON", http.MethodPost, computeBasePath + "/vms", `{"config":`, "invalid request body"},
		{"a short enum name", http.MethodPost, computeBasePath + "/vms/vm-1/attest", `{"pcrBank":"SHA256"}`, `invalid value for enum`},
		{"a short state name", http.MethodGet, computeBasePath + "/vms?states=RUNNING", "", "invalid query parameter states"},
		{"a non-numeric page", http.MethodGet, computeBasePath + "/containers?pagination.page=two", "", "not a valid uint32"},
		{"a flag that is not a bool", http.MethodDelete, computeBasePath + "/vms/vm-1?deleteDisks=yes-please", "", "not a valid bool"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			compute := &fakeComputeService{}

			rec := serveCompute(computeRouter(compute), tc.method, tc.target, tc.body)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.want)
			assert.Nil(t, compute.req)
		})
	}
}

// TestComputeRetiredRoutesAreGone pins that the routes the legacy handlers
// served without a unary ComputeService RPC are not mounted.
func TestComputeRetiredRoutesAreGone(t *testing.T) {
	retired := []struct{ method, path string }{
		{http.MethodPost, "/vms/vm-1/restart"},
		{http.MethodGet, "/vms/vm-1/console"},
		{http.MethodGet, "/containers/ctr-1/logs"},
	}
	for _, route := range retired {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			compute := &fakeComputeService{}

			rec := serveCompute(computeRouter(compute), route.method, computeBasePath+route.path, "")

			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code)
			assert.Nil(t, compute.req)
		})
	}
}

func TestComputeRPC(t *testing.T) {
	t.Run("hands the service the request's TLS connection", func(t *testing.T) {
		compute := &fakeComputeService{}
		req := operatorRequest(http.MethodPost, computeBasePath+"/vms/vm-1/attest", strings.NewReader(""))
		req.TLS = testutil.ServerConnectionState(t)
		rec := httptest.NewRecorder()

		computeRouter(compute).ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		state, transport, ok := channelbind.ConnectionTLS(compute.ctx)
		require.True(t, ok, "the RPC context must record the connection")
		assert.Same(t, req.TLS, state)
		assert.Equal(t, channelbind.TransportREST, transport)
	})

	t.Run("an empty body is the zero request", func(t *testing.T) {
		compute := &fakeComputeService{}

		rec := serveCompute(computeRouter(compute), http.MethodPost, computeBasePath+"/containers", "")

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, proto.Equal(&platformv1.CreateContainerRequest{}, compute.req), "%v", compute.req)
	})

	t.Run("no compute service is 503", func(t *testing.T) {
		rec := serveCompute(computeRouter(nil), http.MethodGet, computeBasePath+"/vms", "")

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, ErrComputeServiceNotAvailable{}.Error(), decodeTPMError(t, rec).Error)
	})

	t.Run("a response that cannot be encoded is 500", func(t *testing.T) {
		// protojson refuses a string field that is not valid UTF-8.
		compute := &fakeComputeService{resp: &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "\xff"}}}

		rec := serveCompute(computeRouter(compute), http.MethodGet, computeBasePath+"/vms/vm-1", "")

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "encode_response")
	})

	statuses := []struct {
		err  error
		want int
	}{
		{status.Error(codes.InvalidArgument, "vm_id is required"), http.StatusBadRequest},
		{status.Error(codes.NotFound, "no such vm"), http.StatusNotFound},
		{status.Error(codes.FailedPrecondition, "vm is running"), http.StatusBadRequest},
		{status.Error(codes.PermissionDenied, "denied"), http.StatusForbidden},
		{status.Error(codes.Unimplemented, "no VM backend"), http.StatusNotImplemented},
		{status.Error(codes.Unavailable, "no orchestrator"), http.StatusServiceUnavailable},
		{errors.New("not a status error"), http.StatusInternalServerError},
	}
	for _, tc := range statuses {
		t.Run("maps "+tc.err.Error(), func(t *testing.T) {
			rec := serveCompute(computeRouter(&fakeComputeService{err: tc.err}), http.MethodGet, computeBasePath+"/vms/vm-1", "")

			assert.Equal(t, tc.want, rec.Code)
			assert.Contains(t, rec.Body.String(), status.Convert(tc.err).Message())
		})
	}
}

func TestComputeHandlerErrors(t *testing.T) {
	assert.Equal(t, "compute service not available", ErrComputeServiceNotAvailable{}.Error())
}
