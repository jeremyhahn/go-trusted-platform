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

package grpc

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// EntityPCRBaselineToProto maps a profile's recorded PCR baseline onto its
// wire form for the read side of every pb-carrying transport (gRPC, Unix and
// the live QUIC dispatcher). There is deliberately no inverse: the baseline
// is written by the verifier (trust on first use) or a signed manifest, never
// by a caller, so pb -> entity conversions ignore an incoming pcr_baseline
// (#373, #448). A nil baseline maps to nil so an unset field stays unset
// rather than becoming an empty message a client would render as a baseline
// of nothing.
func EntityPCRBaselineToProto(b *entities.PCRBaseline) *platformv1.PCRBaseline {
	if b == nil {
		return nil
	}
	pb := &platformv1.PCRBaseline{
		Source:               string(b.Source),
		RecordedFromDeviceId: b.RecordedFromDeviceID,
	}
	if len(b.Values) > 0 {
		pb.Values = make(map[uint32][]byte, len(b.Values))
		for idx, digest := range b.Values {
			if idx < 0 {
				// The entity validator rejects negative indices; a stored
				// baseline that carries one anyway is not something the
				// unsigned wire map can express, so it is dropped rather
				// than wrapped into a bogus high register.
				continue
			}
			pb.Values[uint32(idx)] = digest
		}
	}
	if !b.RecordedAt.IsZero() {
		pb.RecordedAt = timestamppb.New(b.RecordedAt)
	}
	return pb
}
