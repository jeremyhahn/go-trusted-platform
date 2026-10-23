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

// tpmCertifyRequestEncoders and tpmCertifyResponseDecoders carry the TPM
// Certify RPC over the TPM2 category (SubOpTPM2Certify), in the wire shape
// the server's handleCertify decodes.
var tpmCertifyRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.TPMService_Certify_FullMethodName: requestEncoder(platformv1.TPMService_Certify_FullMethodName,
		func(r *platformv1.CertifyRequest) (interface{}, error) {
			return &quicwire.TPM2CertifyRequest{
				KeyHandle:   r.GetKeyHandle(),
				KeyPassword: r.GetKeyPassword(),
				Nonce:       r.GetNonce(),
			}, nil
		}),
}

var tpmCertifyResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.TPMService_Certify_FullMethodName: responseDecoder(platformv1.TPMService_Certify_FullMethodName,
		func(w *quicwire.TPM2CertifyResponse, out *platformv1.CertifyResponse) error {
			out.CertifyInfo = w.CertifyInfo
			out.Signature = w.Signature
			out.SignatureAlgorithm = w.SignatureAlgorithm
			out.CertifyInfoSignature = w.CertifyInfoSignature
			out.AttestingKeyPublic = w.AttestingKeyPublic
			out.AttestedKeyPublic = w.AttestedKeyPublic
			out.AttestingKeyPublicArea = w.AttestingKeyPublicArea
			out.AttestedKeyPublicArea = w.AttestedKeyPublicArea
			out.Nonce = w.Nonce
			return nil
		}),
}

func init() {
	registerCategoryCodecs(tpmCertifyRequestEncoders, tpmCertifyResponseDecoders)
}
