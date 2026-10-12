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

// Package cawire translates the daemon's legacy CA certificate values — the
// string enums and unix-second times the REST and QUIC handlers emit — into
// the pb values the gRPC service sends, so a certificate decoded on any
// transport compares equal.
package cawire

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// statuses mirrors the gRPC service's getCertificateStatus: a certificate
// not yet inside its validity window is PENDING.
var statuses = map[string]platformv1.CertificateStatus{
	"VALID":         platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
	"NOT_YET_VALID": platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING,
	"EXPIRED":       platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
	"REVOKED":       platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
}

// keyAlgorithms mirrors the gRPC service's x509AlgorithmToProto, which
// reports the family, not the key size.
var keyAlgorithms = map[string]platformv1.KeyAlgorithm{
	"RSA":     platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
	"ECDSA":   platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
	"ED25519": platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519,
}

// keyAlgorithmNames names each pb key algorithm the way the daemon's REST,
// QUIC and MCP issue requests accept it. UNSPECIFIED is the empty string,
// which every handler defaults to ECDSA, as the gRPC service does.
var keyAlgorithmNames = map[platformv1.KeyAlgorithm]string{
	platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: "",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    "RSA-2048",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    "RSA-3072",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    "RSA-4096",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  "ECDSA-P256",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  "ECDSA-P384",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:  "ECDSA-P521",
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     "ED25519",
}

// ErrUnknownKeyAlgorithm reports a pb key algorithm with no daemon name.
// The gRPC service refuses the same value, so the SDK refuses it before it
// reaches a transport that would silently default it.
type ErrUnknownKeyAlgorithm struct {
	Algorithm platformv1.KeyAlgorithm
}

func (e ErrUnknownKeyAlgorithm) Error() string {
	return "unsupported key algorithm: " + e.Algorithm.String()
}

// KeyAlgorithmName names a pb key algorithm for a daemon issue request.
func KeyAlgorithmName(alg platformv1.KeyAlgorithm) (string, error) {
	name, ok := keyAlgorithmNames[alg]
	if !ok {
		return "", ErrUnknownKeyAlgorithm{Algorithm: alg}
	}
	return name, nil
}

// Status maps a daemon status string to its pb value; an unknown string is
// UNSPECIFIED.
func Status(s string) platformv1.CertificateStatus {
	return statuses[s]
}

// KeyAlgorithm maps a daemon key-algorithm string to its pb value; an
// unknown string, including the daemon's "UNKNOWN", is UNSPECIFIED.
func KeyAlgorithm(s string) platformv1.KeyAlgorithm {
	return keyAlgorithms[s]
}

// Time converts a unix-second time to a pb timestamp.
func Time(unix int64) *timestamppb.Timestamp {
	return timestamppb.New(time.Unix(unix, 0))
}
