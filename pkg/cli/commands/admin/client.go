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

package admin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// DefaultBundleDir is where qrdb first-boot writes the system admin's
// credential bundle on a deployed node.
const DefaultBundleDir = "/var/lib/trusted-platform/quicbaas/admin"

// DefaultAPI is the loopback REST endpoint the daemon serves, used when
// the command runs on the node itself.
const DefaultAPI = "https://127.0.0.1:8443"

// claimPaths are the ceremony's REST endpoints, relative to the API root.
const (
	statusPath    = "/api/v1/admin/claim/status"
	challengePath = "/api/v1/admin/claim/challenge"
	verifyPath    = "/api/v1/admin/claim/verify"
)

// bundle is the operator's firstboot admin credential.
type bundle struct {
	certPEM []byte
	cert    *x509.Certificate
	signer  crypto.Signer
}

// loadBundle reads admin.crt and admin.key out of dir.
//
// The private key never passes through os.ReadFile.
// memguard.NewMemoryEnclaveFromFile reads it into the stack's protected
// memory — the mlocked, canary-guarded region re-exported through the
// sanctioned quicbaas/sdk/go/xkms path — through a single size-exact
// transfer slice that is wiped on every path, and the enclave is destroyed
// deterministically on return. The certificate is public and is read
// normally.
//
// Two residues remain, both bounded and both upstream:
//
//   - The encoded key's one transfer copy. The sanctioned re-export
//     exposes only NewBufferFromBytes, which copies bytes that already
//     exist and then FREEZES the region, so no locked buffer can be
//     allocated first and filled in place. Reaching past the re-export to
//     the mutable allocator underneath is what doc 00 L1/L8 forbid.
//   - The PARSED key. tls.X509KeyPair returns stdlib crypto types that own
//     their own allocations and expose no scrub, and the quicbaas SDK's own
//     mTLS option loads client identity with tls.LoadX509KeyPair
//     (sdk/go/options.go:423, sdk/go/transport/tls.go:54) — routing through
//     the SDK would reproduce the same copy, not remove it. The stack's
//     protected KEYSTORE is a server-side abstraction: it holds keys it
//     generated, not a PEM file the operator already has on disk.
//
// Both close when the SDK re-exports an allocate-then-fill buffer and a
// protected-memory signer; the gap is reported upstream rather than worked
// around here. The residue is bounded: this runs on the node, as a user who
// can already read the 0600 root-only key file, for the lifetime of one
// command. See docs/security/protected-memory.md.
func loadBundle(dir string) (*bundle, error) {
	certPath := filepath.Join(dir, "admin.crt")
	keyPath := filepath.Join(dir, "admin.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, ErrBundleUnreadable{Path: certPath, Cause: err}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrBundleUnreadable{Path: certPath}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrBundleUnreadable{Path: certPath, Cause: err}
	}

	keyEnclave, err := memguard.NewMemoryEnclaveFromFile(keyPath)
	if err != nil {
		// A file that cannot be read is a bundle problem the operator
		// fixes with a path or a permission; a region that cannot be
		// locked is a host limit. They are reported distinctly because
		// the remedies have nothing in common.
		var unreadable memguard.ErrFileUnreadable
		if errors.As(err, &unreadable) {
			return nil, ErrBundleUnreadable{Path: keyPath, Cause: err}
		}
		return nil, ErrProtectedMemoryUnavailable{Cause: err}
	}
	defer keyEnclave.Destroy()

	var signer crypto.Signer
	if err := keyEnclave.Open(func(keyPEM []byte) error {
		keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return ErrBundleUnreadable{Path: keyPath, Cause: err}
		}
		parsed, ok := keyPair.PrivateKey.(crypto.Signer)
		if !ok {
			return ErrBundleUnreadable{Path: keyPath}
		}
		signer = parsed
		return nil
	}); err != nil {
		return nil, err
	}
	return &bundle{certPEM: certPEM, cert: cert, signer: signer}, nil
}

// sign produces the possession proof over challenge. ECDSA and RSA sign
// the SHA-256 digest; Ed25519 signs the challenge unhashed, matching what
// the server verifies.
func (b *bundle) sign(challenge []byte) ([]byte, error) {
	if _, ok := b.signer.Public().(ed25519.PublicKey); ok {
		return b.signer.Sign(rand.Reader, challenge, crypto.Hash(0))
	}
	digest := sha256.Sum256(challenge)
	return b.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// claimClient talks to the daemon's pre-auth claim endpoints.
type claimClient struct {
	api  string
	http *http.Client
}

// newClaimClient builds an HTTPS client for the claim ceremony. When
// caFile is set the daemon's certificate must chain to it; otherwise the
// host trust store is used. serverName overrides the SNI and
// certificate-verification hostname, carrying the active context's
// server-name setting through to a ceremony that dials by address.
// There is deliberately no "insecure" escape hatch: the ceremony hands a
// claim token to whatever answers, so an unauthenticated server would be
// handed the operator's proof.
func newClaimClient(api, caFile, serverName string) (*claimClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, ErrBundleUnreadable{Path: caFile, Cause: err}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, ErrBundleUnreadable{Path: caFile}
		}
		tlsConfig.RootCAs = pool
	}
	return &claimClient{
		api: api,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// envelope is the platform's standard REST response wrapper.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// call issues a request and unwraps the platform response envelope into
// out. A non-2xx status, or a 2xx envelope reporting failure, is an error.
func (c *claimClient) call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrDaemonUnreachable{Endpoint: c.api, Cause: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrClaimRefused{Status: resp.StatusCode, Reason: string(raw)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !env.Success {
		return ErrClaimRefused{Status: resp.StatusCode, Reason: env.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Payload, out)
}

// statusResponse mirrors adminclaim.StatusResponse.
type statusResponse struct {
	Claimed  bool   `json:"claimed"`
	Username string `json:"username"`
	TenantID string `json:"tenant_id"`
}

// challengeResponse mirrors adminclaim.ChallengeResponse.
type challengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// verifyRequest mirrors adminclaim.ProveRequest.
type verifyRequest struct {
	Challenge      string `json:"challenge"`
	CertificatePEM string `json:"certificate_pem"`
	Signature      []byte `json:"signature"`
}

// verifyResponse mirrors adminclaim.VerifyResponse.
type verifyResponse struct {
	ClaimToken string    `json:"claim_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (c *claimClient) status(ctx context.Context) (*statusResponse, error) {
	var out statusResponse
	if err := c.call(ctx, http.MethodGet, statusPath, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *claimClient) challenge(ctx context.Context) (*challengeResponse, error) {
	var out challengeResponse
	if err := c.call(ctx, http.MethodPost, challengePath, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *claimClient) verify(ctx context.Context, req verifyRequest) (*verifyResponse, error) {
	var out verifyResponse
	if err := c.call(ctx, http.MethodPost, verifyPath, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
