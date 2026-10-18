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

//go:build integration

package compute_test

import (
	"os"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// GetCLIPath returns the path to the platformctl binary.
func GetCLIPath() string {
	if p := os.Getenv("PLATFORMCTL_PATH"); p != "" {
		return p
	}
	return "platformctl"
}

// GetRESTEndpoint returns the REST API endpoint for compute tests.
func GetRESTEndpoint() string {
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint for compute tests.
func GetGRPCEndpoint() string {
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint for compute tests.
func GetQUICEndpoint() string {
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint for compute tests.
func GetMCPEndpoint() string {
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path for compute tests.
func GetSocketPath() string {
	return helpers.GetSocketPath()
}

// generateTestVMName generates a unique VM name for testing.
func generateTestVMName(suffix string) string {
	return "test-vm-" + helpers.GenerateUniqueID(suffix)
}

// fullSnapshotConfig builds the memory-and-disk snapshot configuration the
// compute service requires.
func fullSnapshotConfig(opts CreateSnapshotOptions) *pb.SnapshotConfig {
	return &pb.SnapshotConfig{
		Name:           opts.Name,
		Description:    opts.Description,
		MemorySnapshot: true,
		DiskSnapshot:   true,
	}
}

// snapshotSummary converts an SDK snapshot into its test summary.
func snapshotSummary(snapshot *pb.Snapshot) SnapshotSummary {
	return SnapshotSummary{ID: snapshot.GetId(), VMID: snapshot.GetVmId()}
}

func prepareMigrationRequest(opts PrepareMigrationOptions) *pb.PrepareMigrationRequest {
	req := &pb.PrepareMigrationRequest{VmName: opts.VMName, Mode: opts.Mode}
	if opts.Guest != nil {
		req.Spec = &pb.VMMigrationSpec{MemoryMb: opts.Guest.MemoryMB, Cpus: opts.Guest.CPUs}
	}
	return req
}

func migrationReceiverSummary(resp *pb.PrepareMigrationResponse) *MigrationReceiverSummary {
	return &MigrationReceiverSummary{
		ReceiverID:  resp.GetReceiverId(),
		Port:        resp.GetPort(),
		TLSHostname: resp.GetTlsHostname(),
	}
}

// snapshotSummaries converts SDK snapshots into their test summaries.
func snapshotSummaries(snapshots []*pb.Snapshot) []SnapshotSummary {
	summaries := make([]SnapshotSummary, 0, len(snapshots))
	for _, snapshot := range snapshots {
		summaries = append(summaries, snapshotSummary(snapshot))
	}
	return summaries
}

// vmQuote maps an SDK attestation response to the adapter quote.
func vmQuote(resp *pb.AttestVMResponse) *VMQuote {
	return &VMQuote{
		Quote:              resp.GetQuote(),
		Signature:          resp.GetSignature(),
		SignatureAlgorithm: resp.GetSignatureAlgorithm(),
	}
}

// verifyVMAttestationRequest builds the SDK verification request from the
// adapter options.
func verifyVMAttestationRequest(opts VerifyVMAttestationOptions) *pb.VerifyVMAttestationRequest {
	return &pb.VerifyVMAttestationRequest{
		VmId:               opts.VMID,
		Quote:              opts.Quote,
		Signature:          opts.Signature,
		SignatureAlgorithm: opts.SignatureAlgorithm,
		Nonce:              opts.Nonce,
	}
}
