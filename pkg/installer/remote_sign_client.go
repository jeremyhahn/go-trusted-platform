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

package installer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Provisioning endpoint paths on the control plane. They mirror the routes the
// `platformctl provision fetch-config` command and autoinstall.sh already use
// (pkg/provisioning/configdelivery): a single-use nonce, then the EAB+EK
// authenticated remote-sign endpoint. The path strings are duplicated here
// rather than imported because pkg/provisioning/configdelivery imports
// pkg/installer (for SecureBootConfig), so the reverse import would cycle.
const (
	provisionNoncePath = "/api/v1/provisioning/config/nonce"
	provisionSignPath  = "/api/v1/provisioning/sign"
)

// remoteSignHTTPTimeout bounds each control-plane round trip.
const remoteSignHTTPTimeout = 30 * time.Second

// remoteSignProbeDigestLen is the size of the throwaway digest used to retrieve
// the DB certificate before the first real signature (see ensureCertificate). It
// matches a SHA-256 digest so the control plane resolves the SHA-256 hash.
const remoteSignProbeDigestLen = 32

// RemoteSignContext carries the pre-IDevID provisioning identity an install-time
// node presents to have its Secure Boot DB digest signed by the control-plane
// KMS (resign-mode: remote). It mirrors what `platformctl provision fetch-config`
// sends: External Account Binding credentials from the kernel cmdline (eab_kid /
// eab_hmac), the TPM Endorsement Key serial (`platformctl tpm ek-serial`) and
// certificate, and the booting NIC MAC. The DB private key never leaves the
// control plane — only the digest is round-tripped.
//
// A zero value is not usable; callers build it from boot/provisioning inputs and
// pass it to NewInstaller via WithRemoteSignContext. When the context is absent
// or incomplete (e.g. an airgapped install) the installer leaves the remote seam
// nil and resolveSecureBootSigner falls through to on-node key generation.
type RemoteSignContext struct {
	// ServerURL is the control-plane base URL, e.g. "https://platform:8443".
	ServerURL string
	// EABKeyID and EABHMAC are the External Account Binding credentials.
	EABKeyID string
	EABHMAC  string
	// EKSerial is the TPM Endorsement Key serial; at least one of EKSerial or
	// MACAddress must be present (the control plane matches the device on either).
	EKSerial string
	// MACAddress is the booting NIC MAC.
	MACAddress string
	// EKCertB64 is the standard-base64 encoding of the DER TPM EK certificate.
	// It is optional; the control plane requires it only for EK-bound profiles.
	EKCertB64 string
	// HTTPClient is the verified-HTTPS client used for control-plane calls. When
	// nil a default client trusting the system root store is used. It MUST verify
	// the server certificate — InsecureSkipVerify is never set here or upstream.
	HTTPClient *http.Client
}

// ready reports whether the context carries the minimum the control plane
// requires: a server URL, EAB credentials, and at least one device identifier.
func (c *RemoteSignContext) ready() bool {
	if c == nil {
		return false
	}
	if strings.TrimSpace(c.ServerURL) == "" {
		return false
	}
	if c.EABKeyID == "" || c.EABHMAC == "" {
		return false
	}
	return c.EKSerial != "" || c.MACAddress != ""
}

// remoteSignRequest is the JSON body posted to provisionSignPath. Field names
// MUST match the server-side configdelivery.SignRequest. Digest marshals as
// base64 via encoding/json, matching the server's []byte field.
type remoteSignRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EABKeyID   string `json:"eab_key_id"`
	EABHMAC    string `json:"eab_hmac"`
	Nonce      string `json:"nonce"`
	Digest     []byte `json:"digest"`
	KeyRef     string `json:"key_ref,omitempty"`
}

// remoteSignResponse mirrors the server-side configdelivery.SignResponse payload.
type remoteSignResponse struct {
	Signature []byte `json:"signature"`
	CertPEM   []byte `json:"cert_pem"`
}

// remoteNonceResponse mirrors the server-side configdelivery.NonceResponse payload.
type remoteNonceResponse struct {
	Nonce string `json:"nonce"`
}

// webServiceEnvelope is the {code, error, success, payload} response wrapper the
// platform REST layer (pkg/webservice/v1/response) writes around every body. The
// typed payload is decoded from the Payload member. It is declared locally to
// avoid coupling the installer to the webservice package.
type webServiceEnvelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// remoteSignClient is a crypto.Signer that delegates Secure Boot DB signing to
// the control plane's POST /api/v1/provisioning/sign endpoint. Each Sign fetches
// a fresh single-use nonce, posts the digest together with the node's EAB + EK
// identity, and returns the detached signature; the DB private key never leaves
// the control plane. The companion DB certificate returned alongside the
// signature is cached so Public() — and the installer's Authenticode signer plus
// the firmware db enrollment — use exactly the certificate that matches the
// CP-KMS signing key.
type remoteSignClient struct {
	httpClient *http.Client
	serverURL  string
	rsc        *RemoteSignContext
	logger     *logging.Logger

	cert   *x509.Certificate
	public crypto.PublicKey
}

// Compile-time assertion that the remote client is a usable crypto.Signer.
var _ crypto.Signer = (*remoteSignClient)(nil)

// newRemoteSignClient builds an install-time remote DB signer from a complete
// RemoteSignContext. It returns a typed Secure Boot error when the context is
// incomplete so resolveSecureBootSigner can fall through to on-node generation.
func newRemoteSignClient(rsc *RemoteSignContext, logger *logging.Logger) (*remoteSignClient, error) {
	if !rsc.ready() {
		return nil, ErrSecureBoot(
			"remote sign: incomplete provisioning context (need server-url, eab credentials, and ek-serial or mac)", nil)
	}
	httpClient := rsc.HTTPClient
	if httpClient == nil {
		// A default client verifies the server certificate against the system
		// root store. InsecureSkipVerify is never set.
		httpClient = &http.Client{Timeout: remoteSignHTTPTimeout}
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &remoteSignClient{
		httpClient: httpClient,
		serverURL:  strings.TrimRight(rsc.ServerURL, "/"),
		rsc:        rsc,
		logger:     logger,
	}, nil
}

// Public returns the DB certificate's public key once it has been retrieved from
// a sign response (via ensureCertificate or a prior Sign). It is nil before the
// first successful round trip.
func (c *remoteSignClient) Public() crypto.PublicKey {
	return c.public
}

// Sign signs digest with the control-plane Secure Boot DB key and returns the
// detached signature. The crypto.Signer contract supplies an already-hashed
// digest, so the control plane signs it directly. opts is unused: the hash is
// implied by the digest the Authenticode signer produced, and the control plane
// infers it from the digest length.
func (c *remoteSignClient) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return c.signDigest(context.Background(), digest)
}

// signDigest performs one nonce-then-sign round trip and caches the returned DB
// certificate so subsequent Public() calls reflect the CP-KMS signing key.
func (c *remoteSignClient) signDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, ErrSecureBoot("remote sign: empty digest", nil)
	}
	nonce, err := c.fetchNonce(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.postSign(ctx, nonce, digest)
	if err != nil {
		return nil, err
	}
	if len(resp.Signature) == 0 {
		return nil, ErrSecureBoot("remote sign: control plane returned an empty signature", nil)
	}
	if cert, perr := parseRemoteCertPEM(resp.CertPEM); perr != nil {
		return nil, perr
	} else if cert != nil {
		c.cert = cert
		c.public = cert.PublicKey
	}
	return resp.Signature, nil
}

// ensureCertificate populates the cached DB certificate (and Public()) before any
// real UKI signing. The configdelivery /sign endpoint returns the DB certificate
// only alongside a signature — there is no standalone DB-certificate endpoint
// before the node holds an IDevID — so a one-off random probe digest is signed to
// retrieve it; the probe signature is discarded. resolveSecureBootSigner needs
// the certificate up front to build the Authenticode signer and to enroll the
// matching db entry.
func (c *remoteSignClient) ensureCertificate(ctx context.Context) (*x509.Certificate, error) {
	if c.cert != nil {
		return c.cert, nil
	}
	probe := make([]byte, remoteSignProbeDigestLen)
	if _, err := rand.Read(probe); err != nil {
		return nil, ErrSecureBoot("remote sign: generate certificate probe digest", err)
	}
	if _, err := c.signDigest(ctx, probe); err != nil {
		return nil, err
	}
	if c.cert == nil {
		return nil, ErrSecureBoot("remote sign: control plane returned no DB certificate", nil)
	}
	return c.cert, nil
}

// fetchNonce retrieves a fresh single-use nonce from the control plane.
func (c *remoteSignClient) fetchNonce(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+provisionNoncePath, nil)
	if err != nil {
		return "", ErrSecureBoot("remote sign: build nonce request", err)
	}
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return "", err
	}
	var nonce remoteNonceResponse
	if err := decodeEnvelopePayload(body, &nonce); err != nil {
		return "", ErrSecureBoot("remote sign: decode nonce response", err)
	}
	if nonce.Nonce == "" {
		return "", ErrSecureBoot("remote sign: control plane returned an empty nonce", nil)
	}
	return nonce.Nonce, nil
}

// postSign posts the digest with the node's EAB + EK identity and returns the
// detached signature plus the DB certificate.
func (c *remoteSignClient) postSign(ctx context.Context, nonce string, digest []byte) (*remoteSignResponse, error) {
	payload, err := json.Marshal(remoteSignRequest{
		EKSerial:   c.rsc.EKSerial,
		MACAddress: c.rsc.MACAddress,
		EKCert:     c.rsc.EKCertB64,
		EABKeyID:   c.rsc.EABKeyID,
		EABHMAC:    c.rsc.EABHMAC,
		Nonce:      nonce,
		Digest:     digest,
		KeyRef:     "db",
	})
	if err != nil {
		return nil, ErrSecureBoot("remote sign: marshal sign request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+provisionSignPath, bytes.NewReader(payload))
	if err != nil {
		return nil, ErrSecureBoot("remote sign: build sign request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var signResp remoteSignResponse
	if err := decodeEnvelopePayload(body, &signResp); err != nil {
		return nil, ErrSecureBoot("remote sign: decode sign response", err)
	}
	return &signResp, nil
}

// do executes req and returns the response body, mapping any non-200 status to a
// typed ErrRemoteSign carrying the status and (trimmed) body for diagnostics.
func (c *remoteSignClient) do(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, ErrSecureBoot("remote sign: control-plane request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrSecureBoot("remote sign: read control-plane response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ErrRemoteSign{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// installRemoteSignerResolver returns a remoteSignerResolver that performs
// install-time Secure Boot DB signing through the control plane's
// /api/v1/provisioning/sign endpoint (resign-mode: remote, pre-IDevID EAB+EK
// auth). NewInstaller wires it only when ResignMode==remote AND a complete
// RemoteSignContext is present; otherwise the seam stays nil and
// resolveSecureBootSigner falls through to on-node key generation. The returned
// certificate is fetched up front (via a probe) so it can be enrolled into the
// firmware db and embedded in the UKI Authenticode signature, guaranteeing the
// enrolled db matches the CP-KMS signing key.
func installRemoteSignerResolver(rsc *RemoteSignContext, logger *logging.Logger) remoteSignerResolver {
	return func(ctx context.Context, _ *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
		client, err := newRemoteSignClient(rsc, logger)
		if err != nil {
			return nil, nil, err
		}
		cert, err := client.ensureCertificate(ctx)
		if err != nil {
			return nil, nil, err
		}
		return client, cert, nil
	}
}

// decodeEnvelopePayload unwraps the platform REST {code, success, payload}
// envelope and decodes the payload member into v.
func decodeEnvelopePayload(body []byte, v interface{}) error {
	var env webServiceEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	if len(env.Payload) == 0 || string(env.Payload) == "null" {
		return &MessageError{Msg: "response envelope carried no payload"}
	}
	return json.Unmarshal(env.Payload, v)
}

// parseRemoteCertPEM parses the PEM-encoded DB certificate from a sign response.
// An empty cert is reported as (nil, nil) so a signature-only response is not a
// hard error; a malformed cert is a typed Secure Boot error.
func parseRemoteCertPEM(certPEM []byte) (*x509.Certificate, error) {
	if len(certPEM) == 0 {
		return nil, nil
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrSecureBoot("remote sign: DB certificate PEM did not decode", nil)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrSecureBoot("remote sign: parse DB certificate", err)
	}
	return cert, nil
}

// ErrRemoteSign reports a non-200 response from a control-plane provisioning
// call during install-time remote Secure Boot DB signing.
type ErrRemoteSign struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *ErrRemoteSign) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("remote sign: %s %s returned status %d: %s", e.Method, e.Path, e.Status, e.Body)
	}
	return fmt.Sprintf("remote sign: %s %s returned status %d", e.Method, e.Path, e.Status)
}
