//go:build integration

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

package attestation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

// SkipIfNotIntegration skips the test if not running in integration mode
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// DefaultTenantID returns the default tenant ID for tests
func DefaultTenantID() string {
	if id := os.Getenv("ATTESTATION_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant"
}

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("ATTESTATION_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:8443"
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("ATTESTATION_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:10443"
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("ATTESTATION_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:9444"
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("ATTESTATION_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:9445"
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("ATTESTATION_SOCKET_PATH"); path != "" {
		return path
	}
	return "/run/platformd.sock"
}

// GetCLIPath returns the path to the platformctl CLI
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}

// GenerateTestNonce generates a random nonce for testing
func GenerateTestNonce() []byte {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		// Fall back to deterministic nonce for testing
		return []byte("test-nonce-12345678901234567890")
	}
	return nonce
}

// GenerateTestVMID generates a unique VM ID for testing
func GenerateTestVMID(suffix string) string {
	return "test-vm-" + suffix
}

// GenerateTestHostID generates a unique host ID for testing
func GenerateTestHostID(suffix string) string {
	return "test-host-" + suffix
}

// GenerateTestContainerID generates a unique container ID for testing
func GenerateTestContainerID(suffix string) string {
	return "test-container-" + suffix
}

// GenerateTestImageDigest generates a test image digest
func GenerateTestImageDigest(imageName string) string {
	hash := sha256.Sum256([]byte(imageName + "-" + time.Now().String()))
	return "sha256:" + hex.EncodeToString(hash[:])
}

// GenerateTestQuoteData generates mock quote data for testing
func GenerateTestQuoteData() []byte {
	data := make([]byte, 256)
	if _, err := rand.Read(data); err != nil {
		// Fall back to deterministic data
		for i := range data {
			data[i] = byte(i)
		}
	}
	return data
}

// GenerateTestSignature generates a mock signature for testing
func GenerateTestSignature() []byte {
	sig := make([]byte, 256)
	if _, err := rand.Read(sig); err != nil {
		for i := range sig {
			sig[i] = byte(255 - i)
		}
	}
	return sig
}

// GenerateTestPCRValue generates a mock PCR value for testing
func GenerateTestPCRValue(index int) []byte {
	hash := sha256.Sum256([]byte{byte(index), byte(index >> 8)})
	return hash[:]
}

// GenerateTestPCRDigest generates a mock PCR digest for testing
func GenerateTestPCRDigest(indices []int) []byte {
	hasher := sha256.New()
	for _, idx := range indices {
		hasher.Write(GenerateTestPCRValue(idx))
	}
	return hasher.Sum(nil)
}

// GenerateTestAIKPublicKey generates a mock AIK public key for testing
func GenerateTestAIKPublicKey() []byte {
	// Mock RSA-2048 public key (just random bytes for testing)
	key := make([]byte, 270)
	if _, err := rand.Read(key); err != nil {
		for i := range key {
			key[i] = byte(i % 256)
		}
	}
	return key
}

// GenerateTestEKCertPEM generates a mock EK certificate PEM for testing
func GenerateTestEKCertPEM(vmID, hostID string) string {
	// This is just a placeholder - in real tests, use actual certificates
	return "-----BEGIN CERTIFICATE-----\nMIIB...(mock EK cert for " + vmID + " on " + hostID + ")...\n-----END CERTIFICATE-----"
}

// GenerateTestMerkleRoot generates a mock Merkle root for testing
func GenerateTestMerkleRoot(hostAttest, vmAttests [][]byte) []byte {
	hasher := sha256.New()
	hasher.Write(hostAttest[0])
	hasher.Write(hostAttest[1])
	for _, vm := range vmAttests {
		hasher.Write(vm)
	}
	return hasher.Sum(nil)
}

// DefaultHashAlgorithm returns the default hash algorithm for tests
func DefaultHashAlgorithm() string {
	return "sha256"
}

// DefaultPCRIndices returns the default PCR indices for tests.
// Includes standard PCRs (0-7) plus the configurable WorkloadPCR index.
func DefaultPCRIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6, 7, WorkloadPCRIndex()}
}

// DefaultWorkloadPCRIndex is the default PCR index for workload measurements.
const DefaultWorkloadPCRIndex = 14

// WorkloadPCRIndex returns the PCR index used for workload measurements.
// Reads from WORKLOAD_PCR_INDEX environment variable if set, otherwise returns default (14).
func WorkloadPCRIndex() int {
	if indexStr := os.Getenv("WORKLOAD_PCR_INDEX"); indexStr != "" {
		// Attempt to parse, silently fall back to default on error
		var index int
		if _, err := fmt.Sscanf(indexStr, "%d", &index); err == nil {
			if index >= 0 && index <= 23 {
				return index
			}
		}
	}
	return DefaultWorkloadPCRIndex
}

// CreateTestHostAttestation creates a test host attestation input
func CreateTestHostAttestation(hostID string) *HostAttestationInput {
	indices := DefaultPCRIndices()
	pcrs := make([]PCRValueResult, len(indices))
	for i, idx := range indices {
		pcrs[i] = PCRValueResult{
			Index:     idx,
			Value:     GenerateTestPCRValue(idx),
			Algorithm: DefaultHashAlgorithm(),
		}
	}

	return &HostAttestationInput{
		QuoteData: GenerateTestQuoteData(),
		Signature: GenerateTestSignature(),
		PCRs:      pcrs,
		PCRDigest: GenerateTestPCRDigest(indices),
	}
}

// CreateTestVMAttestation creates a test VM attestation input
func CreateTestVMAttestation(vmID, hostID string) *VMAttestationInput {
	indices := DefaultPCRIndices()
	pcrs := make([]PCRValueResult, len(indices))
	for i, idx := range indices {
		pcrs[i] = PCRValueResult{
			Index:     idx,
			Value:     GenerateTestPCRValue(idx),
			Algorithm: DefaultHashAlgorithm(),
		}
	}

	return &VMAttestationInput{
		VMID:      vmID,
		HostID:    hostID,
		QuoteData: GenerateTestQuoteData(),
		Signature: GenerateTestSignature(),
		PCRs:      pcrs,
		PCRDigest: GenerateTestPCRDigest(indices),
	}
}

// CreateTestContainerAttestation creates a test container attestation input
func CreateTestContainerAttestation(containerID, imageName string) *ContainerAttestationInput {
	digest := sha256.Sum256([]byte(containerID + imageName))
	return &ContainerAttestationInput{
		ContainerID: containerID,
		ImageDigest: GenerateTestImageDigest(imageName),
		Digest:      digest[:],
		PCRValue:    GenerateTestPCRValue(WorkloadPCRIndex()),
	}
}

// TestPushTarget creates a test push target configuration
func TestPushTarget(id, endpoint, transport string) *PushAttestationOptions {
	return &PushAttestationOptions{
		TargetID:    id,
		Endpoint:    endpoint,
		Transport:   transport,
		ContentType: "application/json",
		Timeout:     30 * time.Second,
	}
}
