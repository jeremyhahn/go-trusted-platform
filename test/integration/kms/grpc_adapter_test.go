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

package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

// The gRPC adapter names statuses and hashes the way the Unix, REST and QUIC
// adapters do (upper case, no dash in SHA-2 names); the multi-protocol suite
// compares them across transports.

func TestStatusProtoToString(t *testing.T) {
	tests := map[pb.KeyStatus]string{
		pb.KeyStatus_KEY_STATUS_ENABLED:          "ENABLED",
		pb.KeyStatus_KEY_STATUS_DISABLED:         "DISABLED",
		pb.KeyStatus_KEY_STATUS_PENDING_DELETION: "PENDING_DELETION",
		pb.KeyStatus_KEY_STATUS_COMPROMISED:      "COMPROMISED",
	}
	for status, want := range tests {
		assert.Equal(t, want, statusProtoToString(status))
	}
}

func TestStatusProtoToString_Unknown(t *testing.T) {
	assert.Equal(t, "UNSPECIFIED", statusProtoToString(pb.KeyStatus(99)))
}

func TestHashAlgorithmProtoToString(t *testing.T) {
	tests := map[pb.HashAlgorithm]string{
		pb.HashAlgorithm_HASH_ALG_SHA256:   "SHA256",
		pb.HashAlgorithm_HASH_ALG_SHA384:   "SHA384",
		pb.HashAlgorithm_HASH_ALG_SHA512:   "SHA512",
		pb.HashAlgorithm_HASH_ALG_SHA3_256: "SHA3-256",
	}
	for alg, want := range tests {
		assert.Equal(t, want, hashAlgorithmProtoToString(alg))
		assert.Equal(t, alg, hashAlgorithmStringToProto(want), "the name must round-trip")
	}
}

func TestHashAlgorithmProtoToString_Unknown(t *testing.T) {
	assert.Equal(t, "UNSPECIFIED", hashAlgorithmProtoToString(pb.HashAlgorithm(99)))
	assert.Equal(t, pb.HashAlgorithm_HASH_ALG_UNSPECIFIED, hashAlgorithmStringToProto("MD5"))
}
