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
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The gRPC, Unix and REST adapters reach the same AttestationService RPCs, so
// they share one mapping between the suite's option/result types and the
// protobuf messages. Only the transport differs between them.

// ErrMissingResponseField reports a daemon response that omits the message an
// operation's result is built from.
type ErrMissingResponseField struct {
	Field string
}

func (e ErrMissingResponseField) Error() string {
	return fmt.Sprintf("response carries no %s", e.Field)
}

// collectVMAttestationRequest builds the CollectVMAttestation request that
// serves both GenerateVMQuote and GetVMAttestation.
func collectVMAttestationRequest(vmID string, nonce []byte, pcrIndices []int, hashAlgorithm string) *platformv1.CollectVMAttestationRequest {
	indices := make([]uint32, len(pcrIndices))
	for i, idx := range pcrIndices {
		indices[i] = uint32(idx)
	}

	return &platformv1.CollectVMAttestationRequest{
		VmId: vmID,
		Config: &platformv1.AttestationQuoteConfig{
			PcrIndices:    indices,
			HashAlgorithm: hashAlgorithmFromString(hashAlgorithm),
		},
		Nonce: nonce,
	}
}

// vmQuoteResult maps a CollectVMAttestation response to a GenerateVMQuote result.
func vmQuoteResult(resp *platformv1.CollectVMAttestationResponse) (*GenerateVMQuoteResult, error) {
	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrMissingResponseField{Field: "attestation"}
	}

	return &GenerateVMQuoteResult{
		QuoteData:     attest.GetQuoteData(),
		Signature:     attest.GetSignature(),
		PCRDigest:     attest.GetPcrDigest(),
		AIKPublicKey:  attest.GetAikPublicKey(),
		Timestamp:     timeFromProto(attest.GetTimestamp()),
		HashAlgorithm: hashAlgorithmToString(attest.GetHashAlgorithm()),
	}, nil
}

// vmAttestationResult maps a CollectVMAttestation response to a
// GetVMAttestation result.
func vmAttestationResult(resp *platformv1.CollectVMAttestationResponse) (*GetVMAttestationResult, error) {
	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrMissingResponseField{Field: "attestation"}
	}

	return &GetVMAttestationResult{
		AttestationID:      attest.GetVmId(),
		VMID:               attest.GetVmId(),
		HostID:             attest.GetHostId(),
		QuoteData:          attest.GetQuoteData(),
		Signature:          attest.GetSignature(),
		SignatureAlgorithm: attest.GetSignatureAlgorithm(),
		Nonce:              attest.GetNonce(),
		PCRs:               pcrValuesFromProto(attest.GetPcrs()),
		PCRDigest:          attest.GetPcrDigest(),
		WorkloadPCR:        attest.GetWorkloadPcr(),
		AIKPublicKey:       attest.GetAikPublicKey(),
		EKCertPEM:          string(attest.GetEkCertificate()),
		Timestamp:          timeFromProto(attest.GetTimestamp()),
		Metadata:           attest.GetMetadata(),
	}, nil
}

// verifyAttestationQuoteRequest builds the VerifyAttestationQuote request for
// VerifyVMAttestation.
func verifyAttestationQuoteRequest(opts VerifyVMAttestationOptions) *platformv1.VerifyAttestationQuoteRequest {
	expectedPCRs := make([]*platformv1.AttestationPCRValue, len(opts.ExpectedPCRs))
	for i, pcrVal := range opts.ExpectedPCRs {
		expectedPCRs[i] = &platformv1.AttestationPCRValue{
			Index: uint32(i),
			Value: pcrVal,
		}
	}

	var quote *platformv1.AttestationQuote
	if opts.Quote != nil {
		quote = &platformv1.AttestationQuote{
			QuoteData:          opts.Quote.QuoteData,
			Signature:          opts.Quote.Signature,
			SignatureAlgorithm: opts.Quote.SignatureAlgorithm,
			Nonce:              opts.Quote.Nonce,
		}
	}

	return &platformv1.VerifyAttestationQuoteRequest{
		Quote:          quote,
		AkPublicKeyPem: opts.AkPublicKeyPem,
		ExpectedNonce:  opts.ExpectedNonce,
		ExpectedPcrs:   expectedPCRs,
	}
}

// verifyVMAttestationResult maps a VerifyAttestationQuote response. The RPC
// returns one verdict, so every check in the result carries it.
func verifyVMAttestationResult(opts VerifyVMAttestationOptions, resp *platformv1.VerifyAttestationQuoteResponse) *VerifyVMAttestationResult {
	var errors []string
	if resp.GetMessage() != "" {
		errors = append(errors, resp.GetMessage())
	}

	return &VerifyVMAttestationResult{
		Valid:          resp.GetVerified(),
		AttestationID:  opts.AttestationID,
		NonceMatch:     resp.GetVerified(),
		SignatureValid: resp.GetVerified(),
		PCRsMatch:      resp.GetVerified(),
		EKTrusted:      resp.GetVerified(),
		Errors:         errors,
	}
}

// buildManifestRequest builds the BuildManifest request; the daemon signs the
// manifest as it builds it.
func buildManifestRequest(opts BuildManifestOptions) *platformv1.BuildManifestRequest {
	return &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        opts.HostID,
			HashAlgorithm: hashAlgorithmFromString(opts.HashAlgorithm),
			Version:       opts.Version,
		},
		IncludeVms:        len(opts.VMAttestations) > 0,
		IncludeContainers: len(opts.ContainerAttestations) > 0,
		Sign:              true,
	}
}

// buildManifestResult maps a BuildManifest response.
func buildManifestResult(resp *platformv1.BuildManifestResponse) (*BuildManifestResult, error) {
	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrMissingResponseField{Field: "manifest"}
	}

	return &BuildManifestResult{
		ManifestID:     manifest.GetId(),
		HostID:         manifest.GetHostId(),
		MerkleRoot:     manifest.GetMerkleRoot(),
		VMCount:        len(manifest.GetVms()),
		ContainerCount: len(manifest.GetContainers()),
		Timestamp:      timeFromProto(manifest.GetTimestamp()),
		Version:        manifest.GetVersion(),
		Metadata:       manifest.GetMetadata(),
	}, nil
}

// storedManifest returns the manifest a GetManifest response carries.
func storedManifest(resp *platformv1.GetManifestResponse) (*platformv1.HostManifest, error) {
	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrMissingResponseField{Field: "manifest"}
	}
	return manifest, nil
}

// getManifestResult maps a GetManifest response.
func getManifestResult(resp *platformv1.GetManifestResponse) (*GetManifestResult, error) {
	manifest, err := storedManifest(resp)
	if err != nil {
		return nil, err
	}

	return &GetManifestResult{
		ManifestID:     manifest.GetId(),
		HostID:         manifest.GetHostId(),
		MerkleRoot:     manifest.GetMerkleRoot(),
		Signature:      manifest.GetSignature(),
		VMCount:        len(manifest.GetVms()),
		ContainerCount: len(manifest.GetContainers()),
		Timestamp:      timeFromProto(manifest.GetTimestamp()),
		Version:        manifest.GetVersion(),
		Metadata:       manifest.GetMetadata(),
	}, nil
}

// verifyManifestRequest builds the VerifyManifest request for a stored
// manifest. VerifyManifest takes the manifest itself, so callers fetch it by
// ID first.
func verifyManifestRequest(manifest *platformv1.HostManifest) *platformv1.VerifyManifestRequest {
	return &platformv1.VerifyManifestRequest{
		Manifest: manifest,
		Config: &platformv1.ManifestVerifierConfig{
			RequireHostAttestation: true,
			VerifyMerkleRoot:       true,
		},
	}
}

// verifyManifestResult maps a VerifyManifest response for the manifest that
// was verified.
func verifyManifestResult(opts VerifyManifestOptions, manifest *platformv1.HostManifest, resp *platformv1.VerifyManifestResponse) (*VerifyManifestResult, error) {
	result := resp.GetResult()
	if result == nil {
		return nil, ErrMissingResponseField{Field: "verification result"}
	}

	hostIDMatch := true
	if opts.ExpectedHostID != "" {
		hostIDMatch = manifest.GetHostId() == opts.ExpectedHostID
	}

	return &VerifyManifestResult{
		Valid:           result.GetStatus() == platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
		ManifestID:      opts.ManifestID,
		SignatureValid:  result.GetSignatureValid(),
		MerkleRootValid: result.GetMerkleRootValid(),
		HostIDMatch:     hostIDMatch,
		SignerTrusted:   result.GetSignatureValid(),
		Errors:          result.GetErrors(),
	}, nil
}

// timeFromProto converts a protobuf timestamp, keeping an absent one as the
// zero time rather than the Unix epoch.
func timeFromProto(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// hashAlgorithmFromString converts a string hash algorithm name to the proto enum.
func hashAlgorithmFromString(algo string) platformv1.AttestationHashAlgorithm {
	hashAlgorithmMap := map[string]platformv1.AttestationHashAlgorithm{
		"sha1":   platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1,
		"sha256": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		"sha384": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384,
		"sha512": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512,
	}

	if v, ok := hashAlgorithmMap[strings.ToLower(algo)]; ok {
		return v
	}
	return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED
}

// hashAlgorithmToString converts the proto enum to a string hash algorithm name.
func hashAlgorithmToString(algo platformv1.AttestationHashAlgorithm) string {
	hashAlgorithmStringMap := map[platformv1.AttestationHashAlgorithm]string{
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1:   "sha1",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256: "sha256",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384: "sha384",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512: "sha512",
	}

	if v, ok := hashAlgorithmStringMap[algo]; ok {
		return v
	}
	return ""
}

// pcrValuesFromProto converts proto PCR values to the test adapter PCRValueResult slice.
func pcrValuesFromProto(pcrs []*platformv1.AttestationPCRValue) []PCRValueResult {
	results := make([]PCRValueResult, len(pcrs))
	for i, pcr := range pcrs {
		results[i] = PCRValueResult{
			Index:     int(pcr.GetIndex()),
			Value:     pcr.GetValue(),
			Algorithm: hashAlgorithmToString(pcr.GetAlgorithm()),
		}
	}
	return results
}
