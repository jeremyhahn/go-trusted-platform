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

package tpm

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmpcr"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ErrUnknownPCRBank is returned for a PCR bank number outside the PCRBank
// enum. proto3 enums are open, so a numeric bank such as 99 decodes; the
// daemon would then match no bank and answer an empty read.
type ErrUnknownPCRBank struct {
	Bank int32
}

func (e ErrUnknownPCRBank) Error() string {
	return fmt.Sprintf("unknown PCR bank %d", e.Bank)
}

// validatePCRsRequest refuses a PCR read selection the TPM cannot answer:
// an index above tpmpcr.MaxIndex or a bank outside the PCRBank enum.
// PCR_BANK_UNSPECIFIED (every bank) is accepted.
func validatePCRsRequest(req *platformv1.GetPCRsRequest) error {
	for _, idx := range req.GetIndices() {
		if idx > tpmpcr.MaxIndex {
			return tpmpcr.ErrInvalidIndex{Index: int(idx)}
		}
	}
	bank := int32(req.GetBank())
	if _, ok := platformv1.PCRBank_name[bank]; !ok {
		return ErrUnknownPCRBank{Bank: bank}
	}
	return nil
}
