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
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Handlers serves /api/v1/compute. Each handler decodes a JSON body into
// the matching protobuf request, merges in path variables (so handlers
// remain RESTful instead of forcing clients to repeat the id in the body)
// and writes back a protojson response with the standard envelope.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.ComputeServiceServer
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied gRPC server into the REST handlers.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.ComputeServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{
		logger:     logger,
		server:     server,
		respWriter: respWriter,
	}
}

func (h *Handlers) ensureAvailable(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "compute"})
		return false
	}
	return true
}

// CreateVM handles POST /api/v1/compute/vms.
func (h *Handlers) CreateVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateVMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateVM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// ListVMs handles GET /api/v1/compute/vms.
func (h *Handlers) ListVMs(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ListVMsRequest{}
	if r.URL.Query().Get("page") != "" || r.URL.Query().Get("page_size") != "" {
		page, err := protorest.QueryUint32(r, "page")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		size, err := protorest.QueryUint32(r, "page_size")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: size}
	}
	resp, err := h.server.ListVMs(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetVM handles GET /api/v1/compute/vms/{id}.
func (h *Handlers) GetVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	id := mux.Vars(r)["id"]
	resp, err := h.server.GetVM(r.Context(), &platformv1.GetVMRequest{Id: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteVM handles DELETE /api/v1/compute/vms/{id}?delete_disks=true.
func (h *Handlers) DeleteVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	deleteDisks, err := protorest.QueryBool(r, "delete_disks")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.DeleteVM(r.Context(), &platformv1.DeleteVMRequest{
		Id:          mux.Vars(r)["id"],
		DeleteDisks: deleteDisks,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// StartVM handles POST /api/v1/compute/vms/{id}/start.
func (h *Handlers) StartVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.StartVM(r.Context(), &platformv1.StartVMRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// StopVM handles POST /api/v1/compute/vms/{id}/stop.
func (h *Handlers) StopVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.StopVMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Id = mux.Vars(r)["id"]
	resp, err := h.server.StopVM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// RebootVM handles POST /api/v1/compute/vms/{id}/reboot.
func (h *Handlers) RebootVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.RebootVMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Id = mux.Vars(r)["id"]
	resp, err := h.server.RebootVM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// SuspendVM handles POST /api/v1/compute/vms/{id}/suspend.
func (h *Handlers) SuspendVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.SuspendVM(r.Context(), &platformv1.SuspendVMRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ResumeVM handles POST /api/v1/compute/vms/{id}/resume.
func (h *Handlers) ResumeVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.ResumeVM(r.Context(), &platformv1.ResumeVMRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetVMMetrics handles GET /api/v1/compute/vms/{id}/metrics.
func (h *Handlers) GetVMMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetVMMetrics(r.Context(), &platformv1.GetVMMetricsRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// MigrateVM handles POST /api/v1/compute/vms/{id}/migrate.
func (h *Handlers) MigrateVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.MigrateVMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.VmId = mux.Vars(r)["id"]
	resp, err := h.server.MigrateVM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// AttachDisk handles POST /api/v1/compute/vms/{id}/disks.
func (h *Handlers) AttachDisk(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.AttachDiskRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.VmId = mux.Vars(r)["id"]
	resp, err := h.server.AttachDisk(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// DetachDisk handles DELETE /api/v1/compute/vms/{id}/disks/{diskId}.
func (h *Handlers) DetachDisk(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	vars := mux.Vars(r)
	resp, err := h.server.DetachDisk(r.Context(), &platformv1.DetachDiskRequest{
		VmId:   vars["id"],
		DiskId: vars["diskId"],
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ResizeDisk handles PATCH /api/v1/compute/vms/{id}/disks/{diskId}.
func (h *Handlers) ResizeDisk(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ResizeDiskRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	vars := mux.Vars(r)
	req.VmId = vars["id"]
	req.DiskId = vars["diskId"]
	resp, err := h.server.ResizeDisk(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateSnapshot handles POST /api/v1/compute/vms/{id}/snapshots.
func (h *Handlers) CreateSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateSnapshotRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.VmId = mux.Vars(r)["id"]
	resp, err := h.server.CreateSnapshot(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// ListSnapshots handles GET /api/v1/compute/vms/{id}/snapshots.
func (h *Handlers) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.ListSnapshots(r.Context(), &platformv1.ListSnapshotsRequest{VmId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteSnapshot handles DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}.
func (h *Handlers) DeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	vars := mux.Vars(r)
	resp, err := h.server.DeleteSnapshot(r.Context(), &platformv1.DeleteSnapshotRequest{
		VmId:       vars["id"],
		SnapshotId: vars["snapshotId"],
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// RestoreSnapshot handles POST /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore.
func (h *Handlers) RestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	vars := mux.Vars(r)
	resp, err := h.server.RestoreSnapshot(r.Context(), &platformv1.RestoreSnapshotRequest{
		VmId:       vars["id"],
		SnapshotId: vars["snapshotId"],
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateContainer handles POST /api/v1/compute/containers.
func (h *Handlers) CreateContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateContainerRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateContainer(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// ListContainers handles GET /api/v1/compute/containers.
func (h *Handlers) ListContainers(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ListContainersRequest{}
	if r.URL.Query().Get("page") != "" || r.URL.Query().Get("page_size") != "" {
		page, err := protorest.QueryUint32(r, "page")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		size, err := protorest.QueryUint32(r, "page_size")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: size}
	}
	resp, err := h.server.ListContainers(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetContainer handles GET /api/v1/compute/containers/{id}.
func (h *Handlers) GetContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetContainer(r.Context(), &platformv1.GetContainerRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteContainer handles DELETE /api/v1/compute/containers/{id}.
func (h *Handlers) DeleteContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	force, err := protorest.QueryBool(r, "force")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	deleteVolumes, err := protorest.QueryBool(r, "delete_volumes")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.DeleteContainer(r.Context(), &platformv1.DeleteContainerRequest{
		Id:            mux.Vars(r)["id"],
		Force:         force,
		DeleteVolumes: deleteVolumes,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// StartContainer handles POST /api/v1/compute/containers/{id}/start.
func (h *Handlers) StartContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.StartContainer(r.Context(), &platformv1.StartContainerRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// StopContainer handles POST /api/v1/compute/containers/{id}/stop.
func (h *Handlers) StopContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.StopContainerRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Id = mux.Vars(r)["id"]
	resp, err := h.server.StopContainer(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ExecContainer handles POST /api/v1/compute/containers/{id}/exec.
func (h *Handlers) ExecContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ExecContainerRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Id = mux.Vars(r)["id"]
	resp, err := h.server.ExecContainer(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetContainerMetrics handles GET /api/v1/compute/containers/{id}/metrics.
func (h *Handlers) GetContainerMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetContainerMetrics(r.Context(), &platformv1.GetContainerMetricsRequest{Id: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// AttestContainer handles POST /api/v1/compute/containers/{id}/attest.
// The body carries the nonce and PCR selection; the container ID comes
// from the path.
func (h *Handlers) AttestContainer(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.AttestContainerRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Id = mux.Vars(r)["id"]
	resp, err := h.server.AttestContainer(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// AttestVM handles POST /api/v1/compute/vms/{id}/attest.
func (h *Handlers) AttestVM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.AttestVMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.VmId = mux.Vars(r)["id"]
	resp, err := h.server.AttestVM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// VerifyVMAttestation handles POST /api/v1/compute/vms/{id}/attest/verify.
func (h *Handlers) VerifyVMAttestation(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.VerifyVMAttestationRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.VmId = mux.Vars(r)["id"]
	resp, err := h.server.VerifyVMAttestation(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
