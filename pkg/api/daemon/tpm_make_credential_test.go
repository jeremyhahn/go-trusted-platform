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

package daemon

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestTPMSimulator_MakeCredentialRefusesAMalformedRequest proves that
// MakeCredential, over gRPC and MCP alike, refuses a request it cannot
// serve as asked before the TPM is touched: an ek_cert without its
// iak_pub (or the reverse) must not fall back to wrapping the challenge
// to the local EK, an empty ak_name on the local-EK path must not reach
// the TPM, and an unparsable ek_cert is a typed InvalidArgument, not an
// untyped x509 error.
func TestTPMSimulator_MakeCredentialRefusesAMalformedRequest(t *testing.T) {
	tpm := newSimulatedTPM(t)
	svc := newTPMGRPCServiceWith(tpm)
	mcp := newMCPProviderWithTPM(tpm)
	ctx := context.Background()
	secret := sha256.Sum256([]byte("malformed-credential-secret"))

	cases := []struct {
		name   string
		akName []byte
		ekCert []byte
		iakPub []byte
		reason string
	}{
		{
			name:   "EKCertWithoutIAKPub",
			akName: simulatedAKName("lopsided-ek"),
			ekCert: []byte{0x30, 0x00},
			reason: "ek_cert and iak_pub must be sent together",
		},
		{
			name:   "IAKPubWithoutEKCert",
			akName: simulatedAKName("lopsided-ek"),
			iakPub: []byte{1, 2, 3},
			reason: "ek_cert and iak_pub must be sent together",
		},
		{
			name:   "EmptyAKNameOnTheLocalPath",
			reason: "ak_name is required",
		},
		{
			name:   "UnparsableEKCert",
			ekCert: []byte("not a certificate"),
			iakPub: []byte{1, 2, 3},
			reason: "ek_cert is not a DER certificate: ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, grpcErr := svc.MakeCredential(ctx, &platformv1.MakeCredentialRequest{
				AkName: tc.akName,
				Secret: secret[:],
				EkCert: tc.ekCert,
				IakPub: tc.iakPub,
			})
			_, mcpErr := mcp.TPMMakeCredential(ctx, tc.akName, secret[:], tc.ekCert, tc.iakPub)

			want := ErrMakeCredentialInvalid{Reason: tc.reason}.Error()
			for transport, err := range map[string]error{"gRPC": grpcErr, "MCP": mcpErr} {
				assert.Equal(t, codes.InvalidArgument, status.Code(err),
					"%s: a malformed MakeCredential is refused as InvalidArgument", transport)
				assert.ErrorContains(t, err, want, "%s: the refusal names the reason", transport)
				if strings.HasSuffix(tc.reason, ": ") {
					assert.Greater(t, len(status.Convert(err).Message()), len(want),
						"%s: the parse refusal carries the x509 cause", transport)
				}
			}
		})
	}
}
