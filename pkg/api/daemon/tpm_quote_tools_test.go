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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// signingTPM quotes like a real TPM: the attestation echoes the qualifying
// data and is RSA-PSS signed by a fresh attestation key, whose PKIX DER it
// keeps so a test can verify the quote it produced.
type signingTPM struct {
	xkmssdk.TrustedPlatformModule
	t        testing.TB
	akPublic []byte
}

func newSigningTPM(t testing.TB) *signingTPM {
	return &signingTPM{t: t}
}

func (s *signingTPM) Quote(_ []uint, qualifyingData []byte) (xkmssdk.Quote, error) {
	quoted := quoteEchoing(qualifyingData)
	signature, akPublic := testutil.SignPSSQuote(s.t, quoted)
	s.akPublic = akPublic
	return xkmssdk.Quote{Quoted: quoted, Signature: signature}, nil
}

func (s *signingTPM) IAK() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(s.akPublic)
}

func (s *signingTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		Hash:               crypto.SHA256,
	}, nil
}

// tpmQuoteProvider is the quote half of mcp.ServiceProvider, which both
// daemon providers implement.
type tpmQuoteProvider interface {
	TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error)
	TPMVerifyQuote(ctx context.Context, req *mcp.TPMVerifyQuoteRequest) (interface{}, error)
}

// quoteProviders builds each daemon provider over a TPM; a nil TPM leaves the
// provider without one.
var quoteProviders = map[string]func(tpm xkmssdk.TrustedPlatformModule) tpmQuoteProvider{
	"MCPServiceProvider": func(tpm xkmssdk.TrustedPlatformModule) tpmQuoteProvider {
		return &MCPServiceProvider{logger: slog.Default(), tpm2Service: tpm}
	},
	"PlatformServiceProvider": func(tpm xkmssdk.TrustedPlatformModule) tpmQuoteProvider {
		return NewPlatformServiceProvider(&PlatformServiceProviderConfig{TPM2Service: tpm})
	},
}

// providerQuote is a quote as a provider returns it, decoded from base64.
type providerQuote struct {
	quote, signature, binding []byte
	scheme                    string
}

func quoteThrough(t *testing.T, p tpmQuoteProvider, nonce []byte) providerQuote {
	t.Helper()
	ctx := channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, testutil.ServerConnectionState(t))
	out, err := p.TPMQuote(ctx, nonce, []int{0, 7})
	require.NoError(t, err)
	result, ok := out.(map[string]interface{})
	require.True(t, ok)
	decode := func(field string) []byte {
		text, ok := result[field].(string)
		require.True(t, ok, field)
		raw, err := base64.StdEncoding.DecodeString(text)
		require.NoError(t, err, field)
		return raw
	}
	scheme, ok := result["signature_algorithm"].(string)
	require.True(t, ok)
	return providerQuote{
		quote:     decode("quote"),
		signature: decode("signature"),
		binding:   decode("channel_binding"),
		scheme:    scheme,
	}
}

func verifyThrough(t *testing.T, p tpmQuoteProvider, req *mcp.TPMVerifyQuoteRequest) map[string]interface{} {
	t.Helper()
	out, err := p.TPMVerifyQuote(context.Background(), req)
	require.NoError(t, err)
	result, ok := out.(map[string]interface{})
	require.True(t, ok)
	return result
}

// TestTPMQuoteTools_AQuoteVerifies: a quote produced through either MCP
// provider verifies through it, against the AK the caller names and against
// the platform IAK (#482).
func TestTPMQuoteTools_AQuoteVerifies(t *testing.T) {
	nonce := []byte("provider-nonce")
	for name, provider := range quoteProviders {
		t.Run(name, func(t *testing.T) {
			tpm := newSigningTPM(t)
			p := provider(tpm)
			q := quoteThrough(t, p, nonce)
			assert.Equal(t, testutil.PSSQuoteScheme, q.scheme)
			akPublic := tpm.akPublic

			for label, ak := range map[string][]byte{"ak_public": akPublic, "platform IAK": nil} {
				result := verifyThrough(t, p, &mcp.TPMVerifyQuoteRequest{
					Quote:              q.quote,
					Signature:          q.signature,
					Nonce:              nonce,
					ChannelBinding:     q.binding,
					AKPublic:           ak,
					SignatureAlgorithm: q.scheme,
				})
				assert.Equal(t, true, result["verified"], "%s: %v", label, result["message"])
			}
		})
	}
}

// TestTPMQuoteTools_RefusesAWrongSchemeOrAK: the quote verifies only under
// the scheme it declares and the key that signed it (#482).
func TestTPMQuoteTools_RefusesAWrongSchemeOrAK(t *testing.T) {
	nonce := []byte("provider-refusal")
	_, otherAK := testutil.SignPSSQuote(t, []byte("another key"))
	for name, provider := range quoteProviders {
		t.Run(name, func(t *testing.T) {
			tpm := newSigningTPM(t)
			p := provider(tpm)
			q := quoteThrough(t, p, nonce)

			for label, req := range map[string]*mcp.TPMVerifyQuoteRequest{
				"PKCS#1 v1.5 scheme": {AKPublic: tpm.akPublic, SignatureAlgorithm: x509.SHA256WithRSA.String()},
				"undeclared scheme":  {AKPublic: tpm.akPublic},
				"another AK":         {AKPublic: otherAK, SignatureAlgorithm: q.scheme},
				"malformed AK":       {AKPublic: []byte("not a PKIX key"), SignatureAlgorithm: q.scheme},
			} {
				req.Quote, req.Signature, req.Nonce, req.ChannelBinding = q.quote, q.signature, nonce, q.binding
				result := verifyThrough(t, p, req)
				assert.Equal(t, false, result["verified"], label)
				assert.Contains(t, result["message"], "signature_verification_failed", label)
			}
		})
	}
}

// TestTPMQuoteTools_RefusesAnUnboundQuote: a quote request with no TLS
// connection to bind is refused with the typed binding error.
func TestTPMQuoteTools_RefusesAnUnboundQuote(t *testing.T) {
	for name, provider := range quoteProviders {
		t.Run(name, func(t *testing.T) {
			tpm := newSigningTPM(t)
			ctx := channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, nil)
			_, err := provider(tpm).TPMQuote(ctx, []byte("nonce"), []int{0})
			requireBindingRefusal(t, err, channelbind.TransportMCP)
			assert.Nil(t, tpm.akPublic, "the TPM must not quote")
		})
	}
}

// TestTPMQuoteTools_WithoutATPM: with no TPM, quote and verify answer that
// the service is not available.
func TestTPMQuoteTools_WithoutATPM(t *testing.T) {
	for name, provider := range quoteProviders {
		t.Run(name, func(t *testing.T) {
			p := provider(nil)
			var unavailable ErrServiceNotAvailable

			_, err := p.TPMQuote(context.Background(), []byte("nonce"), []int{0})
			require.ErrorAs(t, err, &unavailable)

			_, err = p.TPMVerifyQuote(context.Background(), &mcp.TPMVerifyQuoteRequest{Quote: []byte("q")})
			require.ErrorAs(t, err, &unavailable)
		})
	}
}
