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

package sdn

import (
	"crypto/x509/pkix"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// ErrEncodeZoneEmpty is returned when encode_zone_in_cert is true but the
// resolved zone name is empty (no zone could be determined for the device).
type ErrEncodeZoneEmpty struct {
	// Serial is the device serial, when known, for audit correlation.
	Serial string
}

// Error implements the error interface.
func (e ErrEncodeZoneEmpty) Error() string {
	if e.Serial != "" {
		return "sdn: encode_zone_in_cert is true but no zone is configured for device serial " + e.Serial
	}
	return "sdn: encode_zone_in_cert is true but no zone is configured for this certificate"
}

// BuildNetworkZoneExtensions returns the pkix.Extension slice to embed in a
// certificate request when encode_zone_in_cert is enabled. It consults cfg to
// decide whether zone encoding is active. When active:
//   - zoneName must be non-empty; an empty value returns ErrEncodeZoneEmpty.
//   - On success, a one-element slice containing the OIDTPNetworkZone extension
//     is returned.
//
// When cfg is nil or encode_zone_in_cert is false, a nil slice and no error
// are returned so callers can unconditionally append the result.
func BuildNetworkZoneExtensions(cfg *IdentityConfig, zoneName, serial string) ([]pkix.Extension, error) {
	if cfg == nil || !cfg.EncodeZoneInCert {
		return nil, nil
	}
	if zoneName == "" {
		return nil, ErrEncodeZoneEmpty{Serial: serial}
	}
	ext, err := quicbaasca.CreateNetworkZoneExtension(zoneName)
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{ext}, nil
}
