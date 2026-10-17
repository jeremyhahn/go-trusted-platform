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

package dns

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TLSAUsageMax is the highest certificate usage RFC 6698 §2.1.1 defines:
// 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE.
const TLSAUsageMax uint32 = 3

// ErrInvalidTLSAUsage is returned for a TLSA record whose certificate usage
// RFC 6698 §2.1.1 does not define.
type ErrInvalidTLSAUsage struct {
	Usage uint32
}

func (e ErrInvalidTLSAUsage) Error() string {
	return fmt.Sprintf("dns: TLSA certificate usage %d is not 0-%d (RFC 6698 §2.1.1)", e.Usage, TLSAUsageMax)
}

// GRPCStatus classes the refusal as InvalidArgument, so every transport,
// MCP's error classifier included, reports it the same way.
func (e ErrInvalidTLSAUsage) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ValidateTLSAUsage refuses a certificate usage outside 0-3, the values
// RFC 6698 §2.1.1 defines. A record with any other usage could never be
// matched by a DANE client, so it is refused before it is stored. The usage
// is taken as uint32, the gRPC field's width, so it is checked before it is
// narrowed to the record's octet.
func ValidateTLSAUsage(usage uint32) error {
	if usage > TLSAUsageMax {
		return ErrInvalidTLSAUsage{Usage: usage}
	}
	return nil
}
