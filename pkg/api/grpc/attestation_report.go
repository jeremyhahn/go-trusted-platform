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
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AttestationReportToProto converts a container.AttestationReport to a
// protobuf AttestContainerResponse. The pcrBank identifies the bank the
// reported PCR values were read from.
func AttestationReportToProto(report *container.AttestationReport, pcrBank platformv1.PCRBank) *platformv1.AttestContainerResponse {
	if report == nil {
		return nil
	}

	pcrValues := make([]*platformv1.PCRValue, 0, len(report.PCRValues))
	for idx, value := range report.PCRValues {
		pcrValues = append(pcrValues, &platformv1.PCRValue{
			Index: uint32(idx),
			Bank:  pcrBank,
			Value: value,
		})
	}

	return &platformv1.AttestContainerResponse{
		Status: &platformv1.Status{
			Success: report.Verified,
			Message: "attestation completed",
		},
		Quote:         report.Quote,
		Signature:     report.Signature,
		PcrValues:     pcrValues,
		AkPublic:      report.AIKCertificate,
		ContainerId:   report.ContainerID,
		ContainerName: report.ContainerName,
		ImageDigest:   report.ImageDigest,
		ConfigDigest:  report.ConfigDigest,
		Verified:      report.Verified,
		Timestamp:     timestamppb.New(report.Timestamp),
	}
}
