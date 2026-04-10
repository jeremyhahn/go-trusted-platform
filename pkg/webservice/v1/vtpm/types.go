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

package vtpm

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// RestHandler defines the HTTP handler interface for vTPM instance operations.
type RestHandler interface {
	// CreateInstance creates a new vTPM instance.
	// POST /api/v1/vtpm/instances
	CreateInstance(w http.ResponseWriter, r *http.Request)

	// ListInstances lists all vTPM instances.
	// GET /api/v1/vtpm/instances
	ListInstances(w http.ResponseWriter, r *http.Request)

	// GetInstance retrieves a vTPM instance by ID.
	// GET /api/v1/vtpm/instances/{id}
	GetInstance(w http.ResponseWriter, r *http.Request)

	// GetInstanceByProfile retrieves the vTPM instance for a profile.
	// GET /api/v1/vtpm/instances/profile/{profile_id}
	GetInstanceByProfile(w http.ResponseWriter, r *http.Request)

	// DeleteInstance deletes a vTPM instance.
	// DELETE /api/v1/vtpm/instances/{id}
	DeleteInstance(w http.ResponseWriter, r *http.Request)

	// StartInstance starts a vTPM instance.
	// POST /api/v1/vtpm/instances/{id}/start
	StartInstance(w http.ResponseWriter, r *http.Request)

	// StopInstance stops a vTPM instance.
	// POST /api/v1/vtpm/instances/{id}/stop
	StopInstance(w http.ResponseWriter, r *http.Request)

	// GetInstanceStatus returns the running status of a vTPM instance.
	// GET /api/v1/vtpm/instances/{id}/status
	GetInstanceStatus(w http.ResponseWriter, r *http.Request)

	// ExportEKCertificate exports the EK certificate in PEM format.
	// GET /api/v1/vtpm/instances/{id}/ek
	ExportEKCertificate(w http.ResponseWriter, r *http.Request)

	// GetEKFingerprint returns the EK certificate fingerprint.
	// GET /api/v1/vtpm/instances/{id}/ek/fingerprint
	GetEKFingerprint(w http.ResponseWriter, r *http.Request)
}

// VTPMInstanceHandler is an alias for RestHandler for backward compatibility.
type VTPMInstanceHandler = RestHandler

// GeneratorServicer defines the service interface for vTPM generation operations.
type GeneratorServicer interface {
	// Generate creates a new vTPM instance with the specified options.
	Generate(ctx context.Context, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error)

	// GenerateForProfile creates a vTPM instance associated with a device profile.
	GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error)

	// Get retrieves a vTPM instance by ID.
	Get(ctx context.Context, id string) (*vtpm.VTPMInstance, error)

	// GetByProfile retrieves the vTPM instance associated with a device profile.
	GetByProfile(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error)

	// Delete removes a vTPM instance and all its state files.
	Delete(ctx context.Context, id string) error

	// List returns all vTPM instances.
	List(ctx context.Context) ([]*vtpm.VTPMInstance, error)

	// Start starts the swtpm daemon for the vTPM instance.
	Start(ctx context.Context, id string) error

	// Stop stops the swtpm daemon for the vTPM instance.
	Stop(ctx context.Context, id string) error

	// IsRunning checks if the vTPM instance is running.
	IsRunning(id string) bool

	// ExportEKCertificate exports the EK certificate for the vTPM instance.
	ExportEKCertificate(ctx context.Context, id string) (*x509.Certificate, error)

	// GetEKFingerprint returns the EK certificate fingerprint.
	GetEKFingerprint(ctx context.Context, id string) (string, error)

	// Close releases resources held by the generator.
	Close() error
}

// CreateInstanceRequest represents the request body for creating a vTPM instance.
type CreateInstanceRequest struct {
	ProfileID *uint64                `json:"profile_id,omitempty"`
	Config    *InstanceConfigRequest `json:"config,omitempty"`
}

// InstanceConfigRequest represents optional configuration for vTPM creation.
type InstanceConfigRequest struct {
	TPMVersion        string            `json:"tpm_version,omitempty"`
	StatePath         string            `json:"state_path,omitempty"`
	Hostname          string            `json:"hostname,omitempty"`
	EKAlgorithm       string            `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool              `json:"secure_boot_enabled,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// InstanceResponse represents a vTPM instance in API responses.
type InstanceResponse struct {
	ID            string    `json:"id"`
	ProfileID     *uint64   `json:"profile_id,omitempty"`
	StatePath     string    `json:"state_path"`
	SocketPath    string    `json:"socket_path"`
	NVRAMPath     string    `json:"nvram_path"`
	EKFingerprint string    `json:"ek_fingerprint,omitempty"`
	SRKHandle     uint32    `json:"srk_handle"`
	TPMVersion    string    `json:"tpm_version"`
	Running       bool      `json:"running"`
	CreatedAt     time.Time `json:"created_at"`
}

// InstanceListResponse represents a list of vTPM instances in API responses.
type InstanceListResponse struct {
	Instances []InstanceResponse `json:"instances"`
	Total     int                `json:"total"`
}

// InstanceStatusResponse represents the status of a vTPM instance.
type InstanceStatusResponse struct {
	ID         string `json:"id"`
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path,omitempty"`
}

// EKFingerprintResponse represents the EK fingerprint response.
type EKFingerprintResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// SuccessResponse represents a generic success response.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ToInstanceResponse converts a VTPMInstance to an InstanceResponse.
func ToInstanceResponse(instance *vtpm.VTPMInstance) InstanceResponse {
	resp := InstanceResponse{
		ID:            instance.ID,
		StatePath:     instance.StoragePath,
		SocketPath:    instance.SocketPath,
		NVRAMPath:     instance.NVRAMPath,
		EKFingerprint: instance.EKFingerprint,
		SRKHandle:     instance.SRKHandle,
		TPMVersion:    string(instance.Version),
		Running:       instance.Running,
		CreatedAt:     instance.CreatedAt,
	}

	if instance.DeviceProfileID != 0 {
		resp.ProfileID = &instance.DeviceProfileID
	}

	return resp
}

// ToInstanceListResponse converts a slice of VTPMInstance to an InstanceListResponse.
func ToInstanceListResponse(instances []*vtpm.VTPMInstance) InstanceListResponse {
	responses := make([]InstanceResponse, 0, len(instances))
	for _, instance := range instances {
		responses = append(responses, ToInstanceResponse(instance))
	}
	return InstanceListResponse{
		Instances: responses,
		Total:     len(responses),
	}
}
