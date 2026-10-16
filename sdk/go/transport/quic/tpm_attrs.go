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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// tpmAttrsRequestEncoders and tpmAttrsResponseDecoders carry the TPM
// GetCapabilities, GetPlatformAttributes and ExtendPCR RPCs over the TPM2
// category, in the wire shapes the server's handleCapabilities,
// handlePlatformAttributes and handleExtendPCR use. The capability and
// platform-attribute requests are empty and the server reads no payload,
// so they travel as empty-body methods and only ExtendPCR needs a request
// encoder.
var tpmAttrsRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.TPMService_ExtendPCR_FullMethodName: requestEncoder(platformv1.TPMService_ExtendPCR_FullMethodName,
		func(r *platformv1.ExtendPCRRequest) (interface{}, error) {
			return &quicwire.TPM2ExtendPCRRequest{
				PCRIndex: int(r.GetIndex()),
				HashAlg:  r.GetHashAlg(),
				Data:     r.GetData(),
			}, nil
		}),
}

var tpmAttrsResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.TPMService_GetCapabilities_FullMethodName: responseDecoder(platformv1.TPMService_GetCapabilities_FullMethodName,
		func(w *quicwire.TPM2CapabilitiesResponse, out *platformv1.TPMCapabilitiesResponse) error {
			out.Algorithms = w.Algorithms
			out.Commands = w.Commands
			out.EccCurves = w.ECCCurves
			return nil
		}),
	platformv1.TPMService_GetPlatformAttributes_FullMethodName: responseDecoder(platformv1.TPMService_GetPlatformAttributes_FullMethodName,
		func(w *quicwire.TPM2PlatformAttributesResponse, out *platformv1.TPMPlatformAttributesResponse) error {
			out.Device = w.Device
			out.IsFips = w.IsFIPS
			out.PcrExtended = w.PCRExtended
			out.CanSeal = w.CanSeal
			out.IsSimulator = w.IsSimulator
			out.Manufacturer = w.Manufacturer
			out.Ek = tpmKeyRefToPb(w.EK)
			out.Srk = tpmKeyRefToPb(w.SRK)
			out.Iak = tpmKeyRefToPb(w.IAK)
			return nil
		}),
	platformv1.TPMService_ExtendPCR_FullMethodName: responseDecoder(platformv1.TPMService_ExtendPCR_FullMethodName,
		func(w *quicwire.TPM2StatusResponse, out *platformv1.ExtendPCRResponse) error {
			out.Status = &platformv1.Status{Success: w.Success, Message: w.Message}
			return nil
		}),
}

// tpmKeyRefToPb converts a provisioned key reference; an absent key stays
// absent.
func tpmKeyRefToPb(ref *quicwire.TPM2KeyRef) *platformv1.TPMKeyRef {
	if ref == nil {
		return nil
	}
	return &platformv1.TPMKeyRef{Handle: ref.Handle, Algorithm: ref.Algorithm}
}

func init() {
	categoryEmptyBodyMethods[platformv1.TPMService_GetCapabilities_FullMethodName] = struct{}{}
	categoryEmptyBodyMethods[platformv1.TPMService_GetPlatformAttributes_FullMethodName] = struct{}{}
	registerCategoryCodecs(tpmAttrsRequestEncoders, tpmAttrsResponseDecoders)
}
