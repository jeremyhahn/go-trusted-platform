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

package provisioning

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// A diskless node keeps nothing across a reboot but its TPM. Each boot it
// fetches its IDevID chain back by name, proving it holds the IDevID key
// with a signature over the connection's exporter value
// (FetchBootCertificate), then opens an mTLS connection with the TPM-resident IDevID key and answers a quote
// over that connection's exporter value (Client.BootDelivery). The control
// plane derives the same value from its side of the connection, so a quote
// made for one connection cannot be replayed on another (#690).
const (
	// BootChannelLabel is the RFC 8446 §7.5 exporter label the boot quote's
	// nonce is derived under. Both sides derive it; neither sends it. The SDK
	// owns it so the client and the daemon cannot disagree.
	BootChannelLabel = transport.ChannelBindingLabel

	// BootChannelNonceSize is the length of the exported nonce.
	BootChannelNonceSize = transport.ChannelBindingSize

	// BootCertificateProofLabel separates the boot-certificate proof from
	// every other signature the IDevID key makes.
	BootCertificateProofLabel = "go-trusted-platform diskless boot certificate v1"

	// BootCertificatePath serves an identity's recorded IDevID chain to the
	// node that proves it holds the chain's key.
	BootCertificatePath = "/api/v1/device/boot/certificate"

	// BootDeliveryPath is the attested, channel-bound delivery.
	BootDeliveryPath = "/api/v1/device/boot"

	// maxBootResponseBytes bounds a boot response: certificate chains and a
	// profile are a few kilobytes.
	maxBootResponseBytes = 1 << 20
)

// BootQuoteFunc produces the JSON-encoded quote evidence for a boot
// delivery, quoted over the nonce it is given.
type BootQuoteFunc func(ctx context.Context, nonce []byte) ([]byte, error)

// BootChannelNonce derives the boot quote's nonce from a TLS 1.3
// connection. The client quotes over it and the server checks the quote
// against its own derivation; TLS 1.2 is refused because its exporter is
// not bound to the handshake without the extended master secret.
func BootChannelNonce(state *tls.ConnectionState) ([]byte, error) {
	return transport.ExportChannelBinding(state)
}

// FetchBootCertificate fetches the IDevID chain the control plane recorded
// for identity at enrollment. The server is verified against roots. The
// request carries no client certificate, because the chain it returns is
// the one the node needs to present one; instead signer, the TPM-resident
// IDevID key, signs the identity and this connection's exporter value, and
// the control plane answers only a proof that verifies against the chain it
// recorded. A name alone fetches nothing.
func FetchBootCertificate(
	ctx context.Context,
	serverURL string,
	roots *x509.CertPool,
	identity string,
	signer crypto.Signer,
	timeout time.Duration,
) (*BootCertificateResponse, error) {
	if identity == "" {
		return nil, ErrBootIdentityRequired
	}
	if roots == nil {
		return nil, ErrMissingCABundle
	}
	if signer == nil {
		return nil, ErrMissingPrivateKey
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}

	var out BootCertificateResponse
	err := postOnBoundConnection(ctx, serverURL+BootCertificatePath, tlsConfig, timeout, ErrBootCertificateFetchFailed,
		func(_ context.Context, nonce []byte) (any, error) {
			signature, err := SignBootCertificateProof(signer, identity, nonce)
			if err != nil {
				return nil, err
			}
			return BootCertificateRequest{Identity: identity, Signature: signature}, nil
		}, &out)
	if err != nil {
		return nil, err
	}
	// The answer must be for the identity asked about: a chain for another
	// name would make the node present a certificate that is not its own.
	if out.Identity != identity || out.IDevIDChain == "" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidResponse,
			Cause: &MessageError{Msg: "boot certificate response does not carry the requested identity's chain"}}
	}
	return &out, nil
}

// BootDelivery opens one mTLS connection, quotes over its exporter value and
// sends the evidence over that same connection.
func (c *Client) BootDelivery(ctx context.Context, quote BootQuoteFunc) (*BootDeliveryResponse, error) {
	if quote == nil {
		return nil, ErrBootQuoteRequired
	}
	var out BootDeliveryResponse
	err := postOnBoundConnection(ctx, c.config.ServerURL+BootDeliveryPath, c.tlsConfig, c.config.Timeout, ErrBootDeliveryFailed,
		func(ctx context.Context, nonce []byte) (any, error) {
			evidence, err := quote(ctx, nonce)
			if err != nil {
				return nil, err
			}
			return BootDeliveryRequest{Evidence: evidence}, nil
		}, &out)
	if err != nil {
		return nil, err
	}
	if out.Serial == "" || out.IDevIDChain == "" || out.CABundle == "" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidResponse,
			Cause: &MessageError{Msg: "boot delivery response is missing its serial, IDevID chain or CA bundle"}}
	}
	c.logger.Info("Boot delivery received",
		"serial", out.Serial,
		"pcrBaselineSource", out.PCRBaselineSource)
	return &out, nil
}

// boundBodyFunc builds a request body from the connection's exporter value.
type boundBodyFunc func(ctx context.Context, nonce []byte) (any, error)

// postOnBoundConnection opens one TLS 1.3 connection, builds the body from
// that connection's BootChannelNonce and POSTs it as JSON on the same
// connection, decoding a 200 into out. It cannot go through a pooled HTTP
// client: the nonce belongs to a connection, so the request must be written
// on the connection it was derived from. A body that cannot be built fails
// with failed as the sentinel.
func postOnBoundConnection(
	ctx context.Context,
	rawURL string,
	baseTLS *tls.Config,
	timeout time.Duration,
	failed error,
	body boundBodyFunc,
	out any,
) error {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Hostname() == "" {
		return &SentinelCauseError{Sentinel: failed,
			Cause: &MessageError{Msg: "server URL is not an absolute https URL: " + rawURL}}
	}
	address := endpoint.Host
	if endpoint.Port() == "" {
		address = net.JoinHostPort(endpoint.Hostname(), "443")
	}

	ctx, cancel := context.WithTimeout(ctx, orDefaultTimeout(timeout))
	defer cancel()

	tlsConfig := baseTLS.Clone()
	tlsConfig.NextProtos = []string{"http/1.1"}
	dialer := &tls.Dialer{Config: tlsConfig}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}
	conn := raw.(*tls.Conn)
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
		}
	}

	state := conn.ConnectionState()
	nonce, err := BootChannelNonce(&state)
	if err != nil {
		return &SentinelCauseError{Sentinel: failed, Cause: err}
	}
	payload, err := body(ctx, nonce)
	if err != nil {
		return &SentinelCauseError{Sentinel: failed, Cause: err}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return &SentinelCauseError{Sentinel: failed, Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return &SentinelCauseError{Sentinel: failed, Cause: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	if err := req.Write(conn); err != nil {
		return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeBootResponse(resp, out)
}

// BootCertificateProofDigest is the SHA-256 a node signs to fetch its boot
// certificate: the proof label, the identity and the connection's exporter
// value, each label and identity NUL-terminated so no byte can move between
// fields.
func BootCertificateProofDigest(identity string, nonce []byte) []byte {
	msg := make([]byte, 0, len(BootCertificateProofLabel)+len(identity)+len(nonce)+2)
	msg = append(msg, BootCertificateProofLabel...)
	msg = append(msg, 0)
	msg = append(msg, identity...)
	msg = append(msg, 0)
	msg = append(msg, nonce...)
	sum := sha256.Sum256(msg)
	return sum[:]
}

// bootProofPSS is the RSA proof scheme: RSASSA-PSS with SHA-256 and a salt
// as long as the hash, the scheme a TPM signs TLS 1.3 handshakes with.
var bootProofPSS = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

// SignBootCertificateProof signs the proof for identity over nonce with
// signer: RSASSA-PSS for an RSA key, ASN.1 ECDSA for an ECDSA key.
func SignBootCertificateProof(signer crypto.Signer, identity string, nonce []byte) ([]byte, error) {
	if signer == nil {
		return nil, ErrMissingPrivateKey
	}
	var opts crypto.SignerOpts
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		opts = bootProofPSS
	case *ecdsa.PublicKey:
		opts = crypto.SHA256
	default:
		return nil, ErrBootProofKeyUnsupported
	}
	return signer.Sign(rand.Reader, BootCertificateProofDigest(identity, nonce), opts)
}

// VerifyBootCertificateProof checks signature against pub, the key the
// recorded IDevID certifies. A nonce that is not a full exporter value is
// refused, so a proof from an unbound connection never verifies.
func VerifyBootCertificateProof(pub crypto.PublicKey, identity string, nonce, signature []byte) error {
	digest := BootCertificateProofDigest(identity, nonce)
	var ok bool
	switch key := pub.(type) {
	case *rsa.PublicKey:
		ok = rsa.VerifyPSS(key, crypto.SHA256, digest, signature, bootProofPSS) == nil
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(key, digest, signature)
	default:
		return ErrBootProofKeyUnsupported
	}
	if !ok || len(nonce) != BootChannelNonceSize {
		return ErrBootProofInvalid
	}
	return nil
}

// ParseCertificateChain parses the certificates of a PEM chain or bundle in
// the order they appear. Blocks of other types are skipped; a chain with no
// certificate, or with one that does not parse, is refused.
func ParseCertificateChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrCertificateChainInvalid, Cause: err}
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, ErrCertificateChainInvalid
	}
	return chain, nil
}

// decodeBootResponse maps a non-200 status to ErrServerError carrying the
// status and the server's message, and decodes a 200 into out.
func decodeBootResponse(resp *http.Response, out any) error {
	limited := io.LimitReader(resp.Body, maxBootResponseBytes)
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(limited)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrServerError,
				Cause: &MessageError{Msg: fmt.Sprintf("server returned status %d", resp.StatusCode)}}
		}
		return &SentinelCauseError{Sentinel: ErrServerError,
			Cause: &MessageError{Msg: fmt.Sprintf("server returned status %d: %s", resp.StatusCode, bytes.TrimSpace(body))}}
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return &SentinelCauseError{Sentinel: ErrInvalidResponse, Cause: err}
	}
	return nil
}

func orDefaultTimeout(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return 30 * time.Second
	}
	return timeout
}
