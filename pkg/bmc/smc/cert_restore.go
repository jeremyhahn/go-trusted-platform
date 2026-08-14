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

package smc

// Hardware validation status
//
// SSL_DEFAULT via op.cgi has been tested only against httptest fakes that
// model the CGI wire protocol from the SMCIPMITool manual. Before enabling
// this path on real X10/X11 hardware, a HAR capture of the default-SSL
// operation via the iKVM HTML5 UI on the target firmware should be diffed
// against the flow below. See the project task "Validate SMC CGI cert
// restore on real X10 hardware".

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// opSSLDefault is the op.cgi operation that instructs the ATEN BMC to
// regenerate its built-in default/self-signed SSL certificate. This
// op triggers an internal key-generation and self-sign cycle; the BMC
// must then be restarted to activate the new certificate.
//
// Wire protocol reference: SMCIPMITool manual + observed CGI flows.
// Validation status: httptest fakes only — requires real X10 hardware
// validation before production use.
const opSSLDefault = "SSL_DEFAULT"

// ErrDefaultSSLFailed indicates the op.cgi SSL_DEFAULT operation returned
// an error or unexpected response from the BMC.
type ErrDefaultSSLFailed struct {
	StatusCode int
	Body       string
}

// Error implements error.
func (e ErrDefaultSSLFailed) Error() string {
	return fmt.Sprintf("smc: CGI SSL_DEFAULT failed: status=%d: %s", e.StatusCode, truncate(e.Body, 200))
}

// RestoreFactoryCertificate implements bmc.FactoryCertRestorer on the
// Supermicro ATEN CGI CertManager.
//
// SMC CGI restore flow:
//  1. Capture the current certificate DER SHA-256 fingerprint.
//  2. Login to obtain a fresh SID cookie.
//  3. POST op.cgi with op=SSL_DEFAULT to trigger built-in cert regeneration.
//  4. POST /cgi/BMC_reset.cgi to restart the web server.
//  5. Logout (best-effort).
//  6. Wait for the HTTPS port to respond (waitForReady).
//  7. Re-capture the certificate and verify it differs from the pre-restore
//     fingerprint; return ErrFactoryRestoreUnchanged when equal.
//
// Hardware note: the SSL_DEFAULT op code follows the same session/SID
// pattern as SSL_VALIDATE in cgi_cert.go. The op has been tested only
// against httptest fakes. Pending validation on real X10 hardware.
func (m *CertManager) RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error) {
	// Step 1: capture pre-restore fingerprint.
	preCert, err := m.GetWebCertificate(ctx)
	if err != nil {
		return nil, ErrTransport{Op: "restore pre-cert capture", Cause: err}
	}
	preFingerprint := certDERSHA256Hex(preCert)

	// Step 2: login.
	sid, err := m.login(ctx)
	if err != nil {
		return nil, err
	}
	defer m.logout(ctx, sid)

	// Step 3: POST op=SSL_DEFAULT to regenerate the built-in certificate.
	if err := m.defaultSSL(ctx, sid); err != nil {
		return nil, err
	}

	// Step 4: restart the BMC web server.
	if err := m.resetBMC(ctx, sid); err != nil {
		return nil, err
	}

	// Step 5: wait for the HTTPS port to come back online.
	if err := m.waitForReady(ctx); err != nil {
		return nil, err
	}

	// Step 6: re-capture the new certificate.
	postCert, err := m.GetWebCertificate(ctx)
	if err != nil {
		return nil, ErrTransport{Op: "restore post-cert capture", Cause: err}
	}

	// Step 7: verify the certificate actually changed.
	if certDERSHA256Hex(postCert) == preFingerprint {
		return nil, ErrRestoreUnchanged{DERFingerprint: preFingerprint}
	}
	return postCert, nil
}

// ErrRestoreUnchanged is returned by RestoreFactoryCertificate when the
// certificate fingerprint is identical before and after the restore operation.
type ErrRestoreUnchanged struct {
	DERFingerprint string
}

// Error implements error.
func (e ErrRestoreUnchanged) Error() string {
	return fmt.Sprintf("smc: factory cert restore: certificate unchanged after restart (fingerprint=%s)", e.DERFingerprint)
}

// defaultSSL posts op=SSL_DEFAULT to /cgi/op.cgi. On firmware revisions
// that do not recognise the opcode, a 404 is treated as "operation not
// available" and returned as ErrDefaultSSLFailed rather than suppressed, so
// callers can fall through to an alternative path if needed.
func (m *CertManager) defaultSSL(ctx context.Context, sid string) error {
	form := url.Values{}
	form.Set("op", opSSLDefault)
	form.Set("r", fmt.Sprintf("%d", time.Now().UnixMilli()))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiOp, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrTransport{Op: "build SSL_DEFAULT request", Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// #nosec G124 -- outbound request cookie, not a Set-Cookie. Secure,
	// HttpOnly and SameSite are response-cookie attributes; net/http
	// serialises a request cookie as Name=Value only and drops them, so
	// setting them here would change nothing. This is the session ID being
	// presented to the BMC's CGI endpoint over the client's TLS config.
	req.AddCookie(&http.Cookie{Name: cookieSID, Value: sid})
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ErrTransport{Op: "SSL_DEFAULT", Cause: err}
	}
	defer resp.Body.Close()
	// Read body so connection can be reused; limit to 4 KiB.
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode/100 != 2 {
		return ErrDefaultSSLFailed{StatusCode: resp.StatusCode, Body: body}
	}
	return nil
}

// certDERSHA256Hex returns the hex-encoded SHA-256 of a certificate's DER bytes.
// Kept local to avoid importing the parent bmc package unexported helper.
func certDERSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// compile-time check: CertManager implements bmc.FactoryCertRestorer.
var _ bmc.FactoryCertRestorer = (*CertManager)(nil)
