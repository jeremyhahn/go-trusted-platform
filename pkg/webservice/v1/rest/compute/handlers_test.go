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

package compute

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// scriptedComputeServer records the request a handler hands the compute
// service and answers with resp, or with err when it is set.
type scriptedComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
	got  proto.Message
	resp proto.Message
	err  error
}

func answer[T proto.Message](s *scriptedComputeServer, req proto.Message) (T, error) {
	s.got = req
	var zero T
	if s.err != nil {
		return zero, s.err
	}
	return s.resp.(T), nil
}

func (s *scriptedComputeServer) CreateVM(_ context.Context, req *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	return answer[*platformv1.CreateVMResponse](s, req)
}

func (s *scriptedComputeServer) ListVMs(_ context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	return answer[*platformv1.ListVMsResponse](s, req)
}

func (s *scriptedComputeServer) GetVM(_ context.Context, req *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	return answer[*platformv1.GetVMResponse](s, req)
}

func (s *scriptedComputeServer) DeleteVM(_ context.Context, req *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	return answer[*platformv1.DeleteVMResponse](s, req)
}

func (s *scriptedComputeServer) StartVM(_ context.Context, req *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	return answer[*platformv1.StartVMResponse](s, req)
}

func (s *scriptedComputeServer) StopVM(_ context.Context, req *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	return answer[*platformv1.StopVMResponse](s, req)
}

func (s *scriptedComputeServer) RebootVM(_ context.Context, req *platformv1.RebootVMRequest) (*platformv1.RebootVMResponse, error) {
	return answer[*platformv1.RebootVMResponse](s, req)
}

func (s *scriptedComputeServer) SuspendVM(_ context.Context, req *platformv1.SuspendVMRequest) (*platformv1.SuspendVMResponse, error) {
	return answer[*platformv1.SuspendVMResponse](s, req)
}

func (s *scriptedComputeServer) ResumeVM(_ context.Context, req *platformv1.ResumeVMRequest) (*platformv1.ResumeVMResponse, error) {
	return answer[*platformv1.ResumeVMResponse](s, req)
}

func (s *scriptedComputeServer) GetVMMetrics(_ context.Context, req *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	return answer[*platformv1.VMMetricsResponse](s, req)
}

func (s *scriptedComputeServer) MigrateVM(_ context.Context, req *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	return answer[*platformv1.MigrateVMResponse](s, req)
}

func (s *scriptedComputeServer) PrepareMigration(_ context.Context, req *platformv1.PrepareMigrationRequest) (*platformv1.PrepareMigrationResponse, error) {
	return answer[*platformv1.PrepareMigrationResponse](s, req)
}

func (s *scriptedComputeServer) FinalizeMigration(_ context.Context, req *platformv1.FinalizeMigrationRequest) (*platformv1.FinalizeMigrationResponse, error) {
	return answer[*platformv1.FinalizeMigrationResponse](s, req)
}

func (s *scriptedComputeServer) AttachDisk(_ context.Context, req *platformv1.AttachDiskRequest) (*platformv1.AttachDiskResponse, error) {
	return answer[*platformv1.AttachDiskResponse](s, req)
}

func (s *scriptedComputeServer) DetachDisk(_ context.Context, req *platformv1.DetachDiskRequest) (*platformv1.DetachDiskResponse, error) {
	return answer[*platformv1.DetachDiskResponse](s, req)
}

func (s *scriptedComputeServer) ResizeDisk(_ context.Context, req *platformv1.ResizeDiskRequest) (*platformv1.ResizeDiskResponse, error) {
	return answer[*platformv1.ResizeDiskResponse](s, req)
}

func (s *scriptedComputeServer) CreateSnapshot(_ context.Context, req *platformv1.CreateSnapshotRequest) (*platformv1.CreateSnapshotResponse, error) {
	return answer[*platformv1.CreateSnapshotResponse](s, req)
}

func (s *scriptedComputeServer) ListSnapshots(_ context.Context, req *platformv1.ListSnapshotsRequest) (*platformv1.ListSnapshotsResponse, error) {
	return answer[*platformv1.ListSnapshotsResponse](s, req)
}

func (s *scriptedComputeServer) GetSnapshot(_ context.Context, req *platformv1.GetSnapshotRequest) (*platformv1.GetSnapshotResponse, error) {
	return answer[*platformv1.GetSnapshotResponse](s, req)
}

func (s *scriptedComputeServer) DeleteSnapshot(_ context.Context, req *platformv1.DeleteSnapshotRequest) (*platformv1.DeleteSnapshotResponse, error) {
	return answer[*platformv1.DeleteSnapshotResponse](s, req)
}

func (s *scriptedComputeServer) RestoreSnapshot(_ context.Context, req *platformv1.RestoreSnapshotRequest) (*platformv1.RestoreSnapshotResponse, error) {
	return answer[*platformv1.RestoreSnapshotResponse](s, req)
}

func (s *scriptedComputeServer) CreateContainer(_ context.Context, req *platformv1.CreateContainerRequest) (*platformv1.CreateContainerResponse, error) {
	return answer[*platformv1.CreateContainerResponse](s, req)
}

func (s *scriptedComputeServer) ListContainers(_ context.Context, req *platformv1.ListContainersRequest) (*platformv1.ListContainersResponse, error) {
	return answer[*platformv1.ListContainersResponse](s, req)
}

func (s *scriptedComputeServer) GetContainer(_ context.Context, req *platformv1.GetContainerRequest) (*platformv1.GetContainerResponse, error) {
	return answer[*platformv1.GetContainerResponse](s, req)
}

func (s *scriptedComputeServer) DeleteContainer(_ context.Context, req *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	return answer[*platformv1.DeleteContainerResponse](s, req)
}

func (s *scriptedComputeServer) StartContainer(_ context.Context, req *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	return answer[*platformv1.StartContainerResponse](s, req)
}

func (s *scriptedComputeServer) StopContainer(_ context.Context, req *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	return answer[*platformv1.StopContainerResponse](s, req)
}

func (s *scriptedComputeServer) ExecContainer(_ context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	return answer[*platformv1.ExecContainerResponse](s, req)
}

func (s *scriptedComputeServer) GetContainerMetrics(_ context.Context, req *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	return answer[*platformv1.ContainerMetricsResponse](s, req)
}

func (s *scriptedComputeServer) AttestContainer(_ context.Context, req *platformv1.AttestContainerRequest) (*platformv1.AttestContainerResponse, error) {
	return answer[*platformv1.AttestContainerResponse](s, req)
}

func (s *scriptedComputeServer) AttestVM(_ context.Context, req *platformv1.AttestVMRequest) (*platformv1.AttestVMResponse, error) {
	return answer[*platformv1.AttestVMResponse](s, req)
}

func (s *scriptedComputeServer) VerifyVMAttestation(_ context.Context, req *platformv1.VerifyVMAttestationRequest) (*platformv1.VerifyVMAttestationResponse, error) {
	return answer[*platformv1.VerifyVMAttestationResponse](s, req)
}

// serveCompute drives one request through the compute routes mounted under
// /api/v1, as the daemon mounts them. A nil server is passed through as a
// nil interface, the daemon's state before the compute service is wired.
func serveCompute(t *testing.T, server platformv1.ComputeServiceServer, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	parent := mux.NewRouter()
	NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), server, newTestWriter()).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	return rec
}

// decodeEnvelope reads the standard response envelope and, when into is not
// nil, unmarshals its payload into the proto message.
func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder, into proto.Message) restwire.WebServiceResponse {
	t.Helper()
	var env struct {
		restwire.WebServiceResponse
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	if into != nil {
		require.NoError(t, protojson.Unmarshal(env.Payload, into), string(env.Payload))
	}
	return env.WebServiceResponse
}

func done(message string) *platformv1.Status {
	return &platformv1.Status{Success: true, Message: message}
}

// computeRoute is one REST route: the request a client sends, the request
// the service must receive, and the answer the service gives back.
type computeRoute struct {
	name     string
	method   string
	target   string
	body     string // empty for routes that take no body
	wantReq  proto.Message
	resp     proto.Message
	wantCode int
}

// computeRoutes covers every unary compute route. Where a body also names
// the resource, the path value must win.
var computeRoutes = []computeRoute{
	{
		name: "CreateVM", method: http.MethodPost, target: "/api/v1/compute/vms",
		body:     `{"config":{"name":"web"},"start":true}`,
		wantReq:  &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "web"}, Start: true},
		resp:     &platformv1.CreateVMResponse{Status: done("created")},
		wantCode: http.StatusCreated,
	},
	{
		name: "ListVMs", method: http.MethodGet, target: "/api/v1/compute/vms",
		wantReq:  &platformv1.ListVMsRequest{},
		resp:     &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1"}, {Id: "vm-2"}}},
		wantCode: http.StatusOK,
	},
	{
		name: "GetVM", method: http.MethodGet, target: "/api/v1/compute/vms/vm-1",
		wantReq:  &platformv1.GetVMRequest{Id: "vm-1"},
		resp:     &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "vm-1"}},
		wantCode: http.StatusOK,
	},
	{
		name: "DeleteVM", method: http.MethodDelete, target: "/api/v1/compute/vms/vm-1?delete_disks=true",
		wantReq:  &platformv1.DeleteVMRequest{Id: "vm-1", DeleteDisks: true},
		resp:     &platformv1.DeleteVMResponse{Status: done("deleted")},
		wantCode: http.StatusOK,
	},
	{
		name: "StartVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/start",
		wantReq:  &platformv1.StartVMRequest{Id: "vm-1"},
		resp:     &platformv1.StartVMResponse{Status: done("started")},
		wantCode: http.StatusOK,
	},
	{
		name: "StopVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/stop",
		body:     `{"id":"vm-other","force":true,"timeout_seconds":30}`,
		wantReq:  &platformv1.StopVMRequest{Id: "vm-1", Force: true, TimeoutSeconds: 30},
		resp:     &platformv1.StopVMResponse{Status: done("stopped")},
		wantCode: http.StatusOK,
	},
	{
		name: "RebootVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/reboot",
		body:     `{"id":"vm-other","force":true}`,
		wantReq:  &platformv1.RebootVMRequest{Id: "vm-1", Force: true},
		resp:     &platformv1.RebootVMResponse{Status: done("rebooted")},
		wantCode: http.StatusOK,
	},
	{
		name: "SuspendVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/suspend",
		wantReq:  &platformv1.SuspendVMRequest{Id: "vm-1"},
		resp:     &platformv1.SuspendVMResponse{Status: done("suspended")},
		wantCode: http.StatusOK,
	},
	{
		name: "ResumeVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/resume",
		wantReq:  &platformv1.ResumeVMRequest{Id: "vm-1"},
		resp:     &platformv1.ResumeVMResponse{Status: done("resumed")},
		wantCode: http.StatusOK,
	},
	{
		name: "GetVMMetrics", method: http.MethodGet, target: "/api/v1/compute/vms/vm-1/metrics",
		wantReq:  &platformv1.GetVMMetricsRequest{Id: "vm-1"},
		resp:     &platformv1.VMMetricsResponse{Metrics: &platformv1.VMMetrics{CpuUsagePercent: 12.5, MemoryUsedMb: 512}},
		wantCode: http.StatusOK,
	},
	{
		name: "MigrateVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/migrate",
		body: `{"vm_id":"vm-other","destination_host":"node-2","live_migration":true,"bandwidth_limit_mbps":100}`,
		wantReq: &platformv1.MigrateVMRequest{
			VmId: "vm-1", DestinationHost: "node-2", LiveMigration: true, BandwidthLimitMbps: 100,
		},
		resp:     &platformv1.MigrateVMResponse{Status: done("migrating")},
		wantCode: http.StatusOK,
	},
	{
		name: "PrepareMigration", method: http.MethodPost, target: "/api/v1/compute/migrations/prepare",
		body:     `{"vm_name":"web","mode":"live"}`,
		wantReq:  &platformv1.PrepareMigrationRequest{VmName: "web", Mode: "live"},
		resp:     &platformv1.PrepareMigrationResponse{Status: done("listening")},
		wantCode: http.StatusOK,
	},
	{
		name: "FinalizeMigration", method: http.MethodPost, target: "/api/v1/compute/migrations/recv-1/finalize",
		body:     `{"receiver_id":"recv-other","commit":true}`,
		wantReq:  &platformv1.FinalizeMigrationRequest{ReceiverId: "recv-1", Commit: true},
		resp:     &platformv1.FinalizeMigrationResponse{Status: done("committed")},
		wantCode: http.StatusOK,
	},
	{
		name: "AttachDisk", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/disks",
		body:     `{"vm_id":"vm-other","disk":{"id":"disk-2"}}`,
		wantReq:  &platformv1.AttachDiskRequest{VmId: "vm-1", Disk: &platformv1.DiskConfig{Id: "disk-2"}},
		resp:     &platformv1.AttachDiskResponse{Status: done("attached")},
		wantCode: http.StatusCreated,
	},
	{
		name: "DetachDisk", method: http.MethodDelete, target: "/api/v1/compute/vms/vm-1/disks/disk-2",
		wantReq:  &platformv1.DetachDiskRequest{VmId: "vm-1", DiskId: "disk-2"},
		resp:     &platformv1.DetachDiskResponse{Status: done("detached")},
		wantCode: http.StatusOK,
	},
	{
		name: "ResizeDisk", method: http.MethodPatch, target: "/api/v1/compute/vms/vm-1/disks/disk-2",
		body:     `{"vm_id":"vm-other","disk_id":"disk-other","new_size_gb":40}`,
		wantReq:  &platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "disk-2", NewSizeGb: 40},
		resp:     &platformv1.ResizeDiskResponse{Status: done("resized")},
		wantCode: http.StatusOK,
	},
	{
		name: "CreateSnapshot", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/snapshots",
		body:     `{"vm_id":"vm-other","config":{"name":"nightly"}}`,
		wantReq:  &platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{Name: "nightly"}},
		resp:     &platformv1.CreateSnapshotResponse{Status: done("snapshotted")},
		wantCode: http.StatusCreated,
	},
	{
		name: "ListSnapshots", method: http.MethodGet, target: "/api/v1/compute/vms/vm-1/snapshots",
		wantReq:  &platformv1.ListSnapshotsRequest{VmId: "vm-1"},
		resp:     &platformv1.ListSnapshotsResponse{Snapshots: []*platformv1.Snapshot{{Id: "snap-1", VmId: "vm-1"}}},
		wantCode: http.StatusOK,
	},
	{
		name: "GetSnapshot", method: http.MethodGet, target: "/api/v1/compute/vms/vm-1/snapshots/snap-1",
		wantReq:  &platformv1.GetSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
		resp:     &platformv1.GetSnapshotResponse{Snapshot: &platformv1.Snapshot{Id: "snap-1", VmId: "vm-1"}},
		wantCode: http.StatusOK,
	},
	{
		name: "DeleteSnapshot", method: http.MethodDelete, target: "/api/v1/compute/vms/vm-1/snapshots/snap-1",
		wantReq:  &platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
		resp:     &platformv1.DeleteSnapshotResponse{Status: done("deleted")},
		wantCode: http.StatusOK,
	},
	{
		name: "RestoreSnapshot", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/snapshots/snap-1/restore",
		wantReq:  &platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
		resp:     &platformv1.RestoreSnapshotResponse{Status: done("restored")},
		wantCode: http.StatusOK,
	},
	{
		name: "CreateContainer", method: http.MethodPost, target: "/api/v1/compute/containers",
		body: `{"config":{"name":"nginx"},"start":true,"attest_on_create":true}`,
		wantReq: &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{Name: "nginx"}, Start: true, AttestOnCreate: true,
		},
		resp:     &platformv1.CreateContainerResponse{Status: done("created")},
		wantCode: http.StatusCreated,
	},
	{
		name: "ListContainers", method: http.MethodGet, target: "/api/v1/compute/containers",
		wantReq:  &platformv1.ListContainersRequest{},
		resp:     &platformv1.ListContainersResponse{Containers: []*platformv1.Container{{Id: "ctr-1"}}},
		wantCode: http.StatusOK,
	},
	{
		name: "GetContainer", method: http.MethodGet, target: "/api/v1/compute/containers/ctr-1",
		wantReq:  &platformv1.GetContainerRequest{Id: "ctr-1"},
		resp:     &platformv1.GetContainerResponse{Container: &platformv1.Container{Id: "ctr-1"}},
		wantCode: http.StatusOK,
	},
	{
		name: "DeleteContainer", method: http.MethodDelete,
		target:   "/api/v1/compute/containers/ctr-1?force=true&delete_volumes=true",
		wantReq:  &platformv1.DeleteContainerRequest{Id: "ctr-1", Force: true, DeleteVolumes: true},
		resp:     &platformv1.DeleteContainerResponse{Status: done("deleted")},
		wantCode: http.StatusOK,
	},
	{
		name: "StartContainer", method: http.MethodPost, target: "/api/v1/compute/containers/ctr-1/start",
		wantReq:  &platformv1.StartContainerRequest{Id: "ctr-1"},
		resp:     &platformv1.StartContainerResponse{Status: done("started")},
		wantCode: http.StatusOK,
	},
	{
		name: "StopContainer", method: http.MethodPost, target: "/api/v1/compute/containers/ctr-1/stop",
		body:     `{"id":"ctr-other","timeout_seconds":10}`,
		wantReq:  &platformv1.StopContainerRequest{Id: "ctr-1", TimeoutSeconds: 10},
		resp:     &platformv1.StopContainerResponse{Status: done("stopped")},
		wantCode: http.StatusOK,
	},
	{
		name: "ExecContainer", method: http.MethodPost, target: "/api/v1/compute/containers/ctr-1/exec",
		body: `{"id":"ctr-other","command":["ls","-l"],"working_dir":"/srv","tty":true}`,
		wantReq: &platformv1.ExecContainerRequest{
			Id: "ctr-1", Command: []string{"ls", "-l"}, WorkingDir: "/srv", Tty: true,
		},
		resp:     &platformv1.ExecContainerResponse{Status: done("exited 0")},
		wantCode: http.StatusOK,
	},
	{
		name: "GetContainerMetrics", method: http.MethodGet, target: "/api/v1/compute/containers/ctr-1/metrics",
		wantReq:  &platformv1.GetContainerMetricsRequest{Id: "ctr-1"},
		resp:     &platformv1.ContainerMetricsResponse{Metrics: &platformv1.ContainerMetrics{CpuUsagePercent: 3.5, MemoryUsedMb: 64}},
		wantCode: http.StatusOK,
	},
	{
		name: "AttestContainer", method: http.MethodPost, target: "/api/v1/compute/containers/ctr-1/attest",
		body:     `{"id":"ctr-other"}`,
		wantReq:  &platformv1.AttestContainerRequest{Id: "ctr-1"},
		resp:     &platformv1.AttestContainerResponse{Status: done("attested")},
		wantCode: http.StatusOK,
	},
	{
		name: "AttestVM", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/attest",
		body:     `{"vm_id":"vm-other","nonce":"AQI=","pcr_indices":[0,7]}`,
		wantReq:  &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte{1, 2}, PcrIndices: []uint32{0, 7}},
		resp:     &platformv1.AttestVMResponse{Status: done("quoted")},
		wantCode: http.StatusOK,
	},
	{
		name: "VerifyVMAttestation", method: http.MethodPost, target: "/api/v1/compute/vms/vm-1/attest/verify",
		body: `{"vm_id":"vm-other","quote":"cXVvdGU=","signature":"c2ln","nonce":"AQI=","signature_algorithm":"RSASSA-PKCS1v15-SHA256"}`,
		wantReq: &platformv1.VerifyVMAttestationRequest{
			VmId: "vm-1", Quote: []byte("quote"), Signature: []byte("sig"), Nonce: []byte{1, 2},
			SignatureAlgorithm: "RSASSA-PKCS1v15-SHA256",
		},
		resp:     &platformv1.VerifyVMAttestationResponse{Status: done("verified")},
		wantCode: http.StatusOK,
	},
}

func TestComputeHandlers_ForwardTheRequestAndReturnTheAnswer(t *testing.T) {
	for _, route := range computeRoutes {
		t.Run(route.name, func(t *testing.T) {
			server := &scriptedComputeServer{resp: route.resp}

			rec := serveCompute(t, server, route.method, route.target, route.body)

			require.Equal(t, route.wantCode, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(route.wantReq, server.got), "service got %v, want %v", server.got, route.wantReq)
			got := route.resp.ProtoReflect().New().Interface()
			env := decodeEnvelope(t, rec, got)
			assert.True(t, env.Success)
			assert.Equal(t, route.wantCode, env.Code)
			assert.True(t, proto.Equal(route.resp, got), "payload %v, want %v", got, route.resp)
		})
	}
}

func TestComputeHandlers_MapServiceErrorsToHTTPStatus(t *testing.T) {
	for _, route := range computeRoutes {
		t.Run(route.name, func(t *testing.T) {
			server := &scriptedComputeServer{err: status.Error(codes.NotFound, "no such resource")}

			rec := serveCompute(t, server, route.method, route.target, route.body)

			require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			require.NotNil(t, server.got, "the service must be called")
			env := decodeEnvelope(t, rec, nil)
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, "no such resource")
		})
	}
}

func TestComputeHandlers_RefuseEveryRouteWithoutAComputeService(t *testing.T) {
	for _, route := range computeRoutes {
		t.Run(route.name, func(t *testing.T) {
			rec := serveCompute(t, nil, route.method, route.target, route.body)

			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			env := decodeEnvelope(t, rec, nil)
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, "compute service is not available")
		})
	}
}

func TestComputeHandlers_RefuseAMalformedBody(t *testing.T) {
	for _, route := range computeRoutes {
		if route.body == "" {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			server := &scriptedComputeServer{resp: route.resp}

			rec := serveCompute(t, server, route.method, route.target, `{"truncated":`)

			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, server.got, "the service must not be called")
		})
	}
}

func TestComputeHandlers_RefuseAMalformedQuery(t *testing.T) {
	cases := []struct {
		name, method, target string
	}{
		{"ListVMs page_size is not a number", http.MethodGet, "/api/v1/compute/vms?page=1&page_size=ten"},
		{"DeleteVM delete_disks is not a bool", http.MethodDelete, "/api/v1/compute/vms/vm-1?delete_disks=maybe"},
		{"DeleteContainer force is not a bool", http.MethodDelete, "/api/v1/compute/containers/ctr-1?force=maybe"},
		{"DeleteContainer delete_volumes is not a bool", http.MethodDelete, "/api/v1/compute/containers/ctr-1?delete_volumes=maybe"},
		{"ListContainers page is not a number", http.MethodGet, "/api/v1/compute/containers?page=two"},
		{"ListContainers page_size is not a number", http.MethodGet, "/api/v1/compute/containers?page=1&page_size=ten"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedComputeServer{}

			rec := serveCompute(t, server, tc.method, tc.target, "")

			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, server.got, "the service must not be called")
		})
	}
}

func TestComputeHandlers_ListPagesFromTheQueryWithoutABody(t *testing.T) {
	cases := []struct {
		name, target string
		resp, want   proto.Message
	}{
		{
			name: "ListVMs", target: "/api/v1/compute/vms?page=2&page_size=5",
			resp: &platformv1.ListVMsResponse{},
			want: &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 5}},
		},
		{
			name: "ListContainers", target: "/api/v1/compute/containers?page=2&page_size=5",
			resp: &platformv1.ListContainersResponse{},
			want: &platformv1.ListContainersRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 5}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedComputeServer{resp: tc.resp}

			rec := serveCompute(t, server, http.MethodGet, tc.target, "")

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, server.got), "service got %v, want %v", server.got, tc.want)
		})
	}
}
