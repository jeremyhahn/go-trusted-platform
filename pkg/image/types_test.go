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

package image

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureFormat_Constants(t *testing.T) {
	assert.Equal(t, SignatureFormat("cosign"), FormatCosign)
	assert.Equal(t, SignatureFormat("sigstore"), FormatSigstore)
	assert.Equal(t, SignatureFormat("notation"), FormatNotation)
}

func TestSignatureAlgorithm_Constants(t *testing.T) {
	assert.Equal(t, SignatureAlgorithm("RS256"), AlgorithmRSA256)
	assert.Equal(t, SignatureAlgorithm("RS384"), AlgorithmRSA384)
	assert.Equal(t, SignatureAlgorithm("RS512"), AlgorithmRSA512)
	assert.Equal(t, SignatureAlgorithm("ES256"), AlgorithmECDSA256)
	assert.Equal(t, SignatureAlgorithm("ES384"), AlgorithmECDSA384)
	assert.Equal(t, SignatureAlgorithm("ES512"), AlgorithmECDSA512)
}

func TestDigestAlgorithm_Constants(t *testing.T) {
	assert.Equal(t, DigestAlgorithm("sha256"), DigestSHA256)
	assert.Equal(t, DigestAlgorithm("sha384"), DigestSHA384)
	assert.Equal(t, DigestAlgorithm("sha512"), DigestSHA512)
}

func TestImageReference_JSON(t *testing.T) {
	ref := &ImageReference{
		Registry:   "gcr.io",
		Repository: "project/image",
		Tag:        "v1.0.0",
		Digest:     "sha256:abc123",
	}

	data, err := json.Marshal(ref)
	require.NoError(t, err)

	var decoded ImageReference
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, ref.Registry, decoded.Registry)
	assert.Equal(t, ref.Repository, decoded.Repository)
	assert.Equal(t, ref.Tag, decoded.Tag)
	assert.Equal(t, ref.Digest, decoded.Digest)
}

func TestImageSignature_JSON(t *testing.T) {
	sig := &ImageSignature{
		ImageDigest:            "sha256:abc123",
		Timestamp:              time.Now().UTC().Truncate(time.Second),
		Signature:              []byte("signature data"),
		SignatureFormat:        FormatCosign,
		SignatureAlgorithm:     AlgorithmRSA256,
		Annotations:            map[string]string{"key": "value"},
		PayloadDigest:          []byte("digest"),
		PayloadDigestAlgorithm: DigestSHA256,
	}

	data, err := json.Marshal(sig)
	require.NoError(t, err)

	var decoded ImageSignature
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, sig.ImageDigest, decoded.ImageDigest)
	assert.Equal(t, sig.SignatureFormat, decoded.SignatureFormat)
	assert.Equal(t, sig.SignatureAlgorithm, decoded.SignatureAlgorithm)
	assert.Equal(t, sig.Annotations["key"], decoded.Annotations["key"])
}

func TestVerificationResult_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	result := &VerificationResult{
		Verified:           true,
		ImageDigest:        "sha256:abc123",
		SignerIdentity:     "CN=Test Signer",
		SignedAt:           now,
		CertChainSubjects:  []string{"CN=Test Signer", "CN=Test CA"},
		SignatureFormat:    FormatCosign,
		SignatureAlgorithm: AlgorithmRSA256,
		TimestampVerified:  true,
		TimestampedAt:      &now,
		Annotations:        map[string]string{"key": "value"},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded VerificationResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, result.Verified, decoded.Verified)
	assert.Equal(t, result.ImageDigest, decoded.ImageDigest)
	assert.Equal(t, result.SignerIdentity, decoded.SignerIdentity)
	assert.Equal(t, result.SignatureFormat, decoded.SignatureFormat)
	assert.Equal(t, result.TimestampVerified, decoded.TimestampVerified)
}

func TestSigningOptions_JSON(t *testing.T) {
	opts := &SigningOptions{
		KeyPath:         "/path/to/key",
		CertPath:        "/path/to/cert",
		CertChainPath:   "/path/to/chain",
		TimestampServer: "https://tsa.example.com",
		Annotations:     map[string]string{"author": "test"},
		SignatureFormat: FormatCosign,
		Upload:          true,
	}

	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded SigningOptions
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, opts.KeyPath, decoded.KeyPath)
	assert.Equal(t, opts.CertPath, decoded.CertPath)
	assert.Equal(t, opts.TimestampServer, decoded.TimestampServer)
	assert.Equal(t, opts.SignatureFormat, decoded.SignatureFormat)
}

func TestVerificationOptions_JSON(t *testing.T) {
	opts := &VerificationOptions{
		AllowExpired:           true,
		RequireTimestamp:       true,
		VerifyAnnotations:      map[string]string{"key": "value"},
		RequiredSignerIdentity: "CN=Test",
		CheckRevocation:        true,
		CRLEndpoints:           []string{"https://crl.example.com"},
		OCSPEndpoints:          []string{"https://ocsp.example.com"},
		AcceptedFormats:        []SignatureFormat{FormatCosign, FormatSigstore},
	}

	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded VerificationOptions
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, opts.AllowExpired, decoded.AllowExpired)
	assert.Equal(t, opts.RequireTimestamp, decoded.RequireTimestamp)
	assert.Equal(t, opts.RequiredSignerIdentity, decoded.RequiredSignerIdentity)
	assert.Equal(t, opts.CheckRevocation, decoded.CheckRevocation)
}

func TestRegistryAuth_JSON(t *testing.T) {
	auth := &RegistryAuth{
		Username:      "user",
		Password:      "pass",
		Token:         "token123",
		IdentityToken: "identity123",
	}

	data, err := json.Marshal(auth)
	require.NoError(t, err)

	var decoded RegistryAuth
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, auth.Username, decoded.Username)
	assert.Equal(t, auth.Token, decoded.Token)
}

func TestRegistryOptions_JSON(t *testing.T) {
	opts := &RegistryOptions{
		Auth: &RegistryAuth{
			Username: "user",
		},
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: time.Second,
		UserAgent:  "test-agent",
	}

	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded RegistryOptions
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, opts.Auth.Username, decoded.Auth.Username)
	assert.Equal(t, opts.MaxRetries, decoded.MaxRetries)
	assert.Equal(t, opts.UserAgent, decoded.UserAgent)
}

func TestManifestDescriptor_JSON(t *testing.T) {
	desc := &ManifestDescriptor{
		MediaType:   "application/vnd.oci.image.manifest.v1+json",
		Digest:      "sha256:abc123",
		Size:        1024,
		Annotations: map[string]string{"key": "value"},
	}

	data, err := json.Marshal(desc)
	require.NoError(t, err)

	var decoded ManifestDescriptor
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, desc.MediaType, decoded.MediaType)
	assert.Equal(t, desc.Digest, decoded.Digest)
	assert.Equal(t, desc.Size, decoded.Size)
}

func TestSignaturePayload_JSON(t *testing.T) {
	payload := &SignaturePayload{
		Critical: CriticalData{
			Type: "atomic container signature",
			Image: ImageIdentity{
				DockerReference: "registry/image@sha256:abc123",
			},
			Identity: SignerIdentity{
				DockerReference: "registry/image",
			},
		},
		Optional: map[string]interface{}{
			"key": "value",
		},
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)

	var decoded SignaturePayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, payload.Critical.Type, decoded.Critical.Type)
	assert.Equal(t, payload.Critical.Image.DockerReference, decoded.Critical.Image.DockerReference)
}

func TestImageSignature_CertificatePEM(t *testing.T) {
	sig := &ImageSignature{
		ImageDigest:   "sha256:abc123",
		SignerCertPEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		CertChainPEM:  []byte("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"),
	}

	assert.NotEmpty(t, sig.SignerCertPEM)
	assert.NotEmpty(t, sig.CertChainPEM)
}

func TestVerificationOptions_TrustAnchorsPEM(t *testing.T) {
	opts := &VerificationOptions{
		TrustAnchorsPEM:      []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		IntermediateCertsPEM: []byte("-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----"),
	}

	assert.NotEmpty(t, opts.TrustAnchorsPEM)
	assert.NotEmpty(t, opts.IntermediateCertsPEM)
}

func TestVerificationResult_Errors(t *testing.T) {
	result := &VerificationResult{
		Verified:    false,
		Errors:      []string{"error 1", "error 2"},
		Warnings:    []string{"warning 1"},
		ImageDigest: "sha256:abc123",
	}

	assert.Len(t, result.Errors, 2)
	assert.Len(t, result.Warnings, 1)
	assert.False(t, result.Verified)
}
