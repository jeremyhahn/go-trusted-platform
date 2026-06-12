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

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// CGI endpoint paths on X10/X11 ATEN BMC firmware.
const (
	cgiLogin     = "/cgi/login.cgi"
	cgiUploadSSL = "/cgi/upload_ssl.cgi"
	cgiOp        = "/cgi/op.cgi"
	cgiBMCReset  = "/cgi/BMC_reset.cgi"
	cgiLogout    = "/cgi/logout.cgi"

	cookieSID = "SID"

	// opSSLValidate is the op.cgi operation code that asks the BMC to
	// verify the freshly uploaded cert+key pair. Not all firmware
	// revisions require this step; ones that do return "valid" on
	// success and an HTML error page otherwise.
	opSSLValidate = "SSL_VALIDATE"
)

// CertManager implements bmc.CertificateManager via the Supermicro ATEN
// CGI SSL upload flow.
//
// Lifecycle: each mutating operation acquires a fresh SID cookie via
// login.cgi, performs its work, and immediately invalidates the session
// via logout.cgi. Credentials are held in memguard-locked memory for
// the manager's lifetime and scrubbed on Close.
type CertManager struct {
	cfg        *bmc.Config
	username   string
	password   *memguard.Secret
	httpClient *http.Client
	logger     *slog.Logger

	// resetWaitCheck and resetMaxWait bound the post-reset readiness
	// polling loop. Overridable for tests.
	resetWaitCheck time.Duration
	resetMaxWait   time.Duration
}

// Compile-time interface checks.
var _ bmc.CertificateManager = (*CertManager)(nil)
var _ bmc.ManagedCertificateManager = (*CertManager)(nil)

// NewCertManager builds a Supermicro CGI CertificateManager from cfg.
// Credentials are taken from cfg.Username / cfg.Password and wrapped
// into locked memory. The returned manager must be closed when
// finished to release credentials.
func NewCertManager(cfg *bmc.Config, logger *slog.Logger) (*CertManager, error) {
	if cfg == nil {
		return nil, ErrInvalidInput{Field: "config", Reason: "nil"}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Username == "" {
		return nil, ErrInvalidInput{Field: "username", Reason: "required for CGI login"}
	}
	tlsCfg, err := bmc.BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return &CertManager{
		cfg:      cfg,
		username: cfg.Username,
		password: memguard.NewFromString(cfg.Password),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
		logger:         logger,
		resetWaitCheck: 2 * time.Second,
		resetMaxWait:   5 * time.Minute,
	}, nil
}

// Close releases the manager's credential material.
func (m *CertManager) Close() error {
	if m.password != nil {
		m.password.Destroy()
	}
	return nil
}

// Backend reports the active backend.
func (m *CertManager) Backend() bmc.CertBackend {
	return bmc.CertBackendSMCCGI
}

// GetWebCertificate reads the leaf certificate currently presented on
// the BMC's HTTPS port. Implemented via a direct TLS handshake so it
// works on every ATEN firmware revision without any CGI round-trip.
func (m *CertManager) GetWebCertificate(ctx context.Context) (*x509.Certificate, error) {
	tlsCfg, err := bmc.BuildTLSConfig(ctx, m.cfg)
	if err != nil {
		return nil, err
	}
	conn, err := dialTLS(ctx, m.cfg.Address, m.cfg.Port, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, ErrTransport{Op: "peer certificates", Cause: errors.New("BMC presented no peer certificates")}
	}
	return state.PeerCertificates[0], nil
}

// ReplaceWebCertificate uploads a new SSL cert+key to the BMC via the
// CGI upload endpoint, optionally validates the pair via op.cgi, and
// resets the BMC to activate the new certificate.
func (m *CertManager) ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.Secret) error {
	if len(certPEM) == 0 {
		return ErrInvalidInput{Field: "certPEM", Reason: "certificate PEM is empty"}
	}
	if keyPEM == nil || keyPEM.Size() == 0 {
		return ErrInvalidInput{Field: "keyPEM", Reason: "private key is required"}
	}

	sid, err := m.login(ctx)
	if err != nil {
		return err
	}
	defer m.logout(ctx, sid)

	if err := m.uploadSSL(ctx, sid, certPEM, keyPEM); err != nil {
		return err
	}

	// Validate is best-effort: ATEN 4.0+ firmware returns 404 for this op
	// on some revisions because validation already happened during
	// upload_ssl.cgi. Treat 404 and "not supported" as success.
	if err := m.validateSSL(ctx, sid); err != nil {
		var vErr ErrValidateFailed
		if errors.As(err, &vErr) && vErr.StatusCode == http.StatusNotFound {
			m.log("cgi validate step not available on this firmware; continuing")
		} else {
			return err
		}
	}

	if err := m.resetBMC(ctx, sid); err != nil {
		return err
	}

	return m.waitForReady(ctx)
}

// baseURL returns the https://host:port prefix for CGI endpoints.
func (m *CertManager) baseURL() string {
	return fmt.Sprintf("https://%s:%d", m.cfg.Address, m.cfg.Port)
}

// login performs /cgi/login.cgi and returns the SID cookie value.
func (m *CertManager) login(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("name", m.username)
	var sid string
	err := m.password.WithBytes(func(pw []byte) error {
		form.Set("pwd", string(pw))
		body := form.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiLogin, strings.NewReader(body))
		if err != nil {
			return ErrTransport{Op: "build login request", Cause: err}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.httpClient.Do(req)
		if err != nil {
			return ErrTransport{Op: "login", Cause: err}
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode/100 != 2 {
			return ErrLoginFailed{StatusCode: resp.StatusCode, Message: string(respBody)}
		}
		for _, c := range resp.Cookies() {
			if c.Name == cookieSID && c.Value != "" {
				sid = c.Value
				return nil
			}
		}
		// Some firmware returns SID in the response body rather than a
		// Set-Cookie header (older X9/X10 ATEN builds). Accept either.
		if token := extractSIDFromBody(respBody); token != "" {
			sid = token
			return nil
		}
		return ErrNoSessionCookie{}
	})
	return sid, err
}

// uploadSSL performs the multipart POST to /cgi/upload_ssl.cgi. The
// assembled multipart body is wiped from memory after the request
// completes.
func (m *CertManager) uploadSSL(ctx context.Context, sid string, certPEM []byte, keyPEM *memguard.Secret) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	if err := writePart(mw, "cert_file", "cert.pem", certPEM); err != nil {
		return ErrTransport{Op: "build cert part", Cause: err}
	}
	var partErr error
	if err := keyPEM.WithBytes(func(k []byte) error {
		partErr = writePart(mw, "key_file", "key.pem", k)
		return nil
	}); err != nil {
		return err
	}
	if partErr != nil {
		return ErrTransport{Op: "build key part", Cause: partErr}
	}
	if err := mw.Close(); err != nil {
		return ErrTransport{Op: "finalize multipart", Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiUploadSSL, &buf)
	if err != nil {
		zeroBuffer(&buf)
		return ErrTransport{Op: "build upload request", Cause: err}
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: cookieSID, Value: sid})

	resp, err := m.httpClient.Do(req)
	zeroBuffer(&buf) // scrub key material as soon as request has been consumed
	if err != nil {
		return ErrTransport{Op: "upload", Cause: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode/100 != 2 {
		return ErrUploadFailed{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if looksLikeUploadError(body) {
		return ErrUploadFailed{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return nil
}

// validateSSL performs the op.cgi SSL_VALIDATE operation.
func (m *CertManager) validateSSL(ctx context.Context, sid string) error {
	form := url.Values{}
	form.Set("op", opSSLValidate)
	form.Set("r", fmt.Sprintf("%d", time.Now().UnixMilli()))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiOp, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrTransport{Op: "build validate request", Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieSID, Value: sid})
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ErrTransport{Op: "validate", Cause: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return ErrValidateFailed{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if !looksValid(body) {
		return ErrValidateFailed{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return nil
}

// resetBMC asks the BMC to restart so the new certificate takes effect.
func (m *CertManager) resetBMC(ctx context.Context, sid string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiBMCReset, nil)
	if err != nil {
		return ErrTransport{Op: "build reset request", Cause: err}
	}
	req.AddCookie(&http.Cookie{Name: cookieSID, Value: sid})
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ErrTransport{Op: "reset", Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ErrResetFailed{StatusCode: resp.StatusCode}
	}
	return nil
}

// logout is best-effort session invalidation. Errors are logged and
// swallowed — the SID will time out on the BMC side regardless.
func (m *CertManager) logout(ctx context.Context, sid string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL()+cgiLogout, nil)
	if err != nil {
		m.log("logout build failed", "err", err)
		return
	}
	req.AddCookie(&http.Cookie{Name: cookieSID, Value: sid})
	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.log("logout request failed", "err", err)
		return
	}
	resp.Body.Close()
}

// waitForReady polls the BMC HTTPS port until a TLS handshake succeeds
// or the context/deadline fires.
func (m *CertManager) waitForReady(ctx context.Context) error {
	tlsCfg, err := bmc.BuildTLSConfig(ctx, m.cfg)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(m.resetMaxWait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	timer := time.NewTimer(m.resetWaitCheck)
	defer timer.Stop()
	for {
		conn, dialErr := dialTLS(ctx, m.cfg.Address, m.cfg.Port, tlsCfg)
		if dialErr == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return ErrTransport{Op: "wait for BMC ready", Cause: dialErr}
		}
		timer.Reset(m.resetWaitCheck)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// log emits a structured log entry if a logger is configured.
func (m *CertManager) log(msg string, args ...any) {
	if m.logger != nil {
		m.logger.Info("smc: "+msg, args...)
	}
}

// --- helpers ---

// dialTLS opens a TLS connection respecting ctx cancellation.
func dialTLS(ctx context.Context, host string, port int, tlsCfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, ErrTransport{Op: "dial", Cause: err}
	}
	conn := tls.Client(raw, tlsCfg)
	// Run the handshake under the caller's deadline.
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, ErrTransport{Op: "tls handshake", Cause: err}
	}
	return conn, nil
}

// writePart is a small wrapper for file-like multipart parts used by
// uploadSSL. The filename field is required by ATEN BMC — omitting it
// causes the CGI to reject the payload with a 500.
func writePart(mw *multipart.Writer, field, filename string, data []byte) error {
	header := make(map[string][]string)
	header["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filename)}
	header["Content-Type"] = []string{"application/octet-stream"}
	part, err := mw.CreatePart(header)
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	return err
}

// zeroBuffer wipes the contents of buf and resets its length.
func zeroBuffer(buf *bytes.Buffer) {
	b := buf.Bytes()
	for i := range b {
		b[i] = 0
	}
	buf.Reset()
}

// extractSIDFromBody scrapes an SID token from a login.cgi response
// body for older ATEN firmware that puts it in the body instead of a
// Set-Cookie header.
func extractSIDFromBody(body []byte) string {
	const marker = "SID="
	idx := bytes.Index(body, []byte(marker))
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(marker):]
	end := 0
	for end < len(rest) && rest[end] != ';' && rest[end] != ' ' && rest[end] != '\r' && rest[end] != '\n' && rest[end] != '"' {
		end++
	}
	return string(rest[:end])
}

// looksLikeUploadError returns true if the upload response HTML
// contains markers indicating an error. The ATEN UI flashes the same
// HTML shell on success and failure, differing only in an embedded
// message; treat presence of well-known failure phrases as an error.
func looksLikeUploadError(body []byte) bool {
	lower := bytes.ToLower(body)
	needles := [][]byte{
		[]byte("invalid"),
		[]byte("fail"),
		[]byte("error"),
		[]byte("reject"),
	}
	for _, n := range needles {
		if bytes.Contains(lower, n) {
			return true
		}
	}
	return false
}

// looksValid returns true if an op.cgi SSL_VALIDATE body indicates
// success. ATEN firmware variants respond differently: some emit
// plain "valid"/"ok", some return JSON like `{"VALID":1}`, some an
// HTML page containing "Valid Certificate". Accept any of these.
func looksValid(body []byte) bool {
	lower := bytes.ToLower(body)
	positives := [][]byte{
		[]byte("valid"),
		[]byte(`"ok"`),
		[]byte("ok"),
		[]byte(`"1"`),
	}
	for _, p := range positives {
		if bytes.Contains(lower, p) {
			return true
		}
	}
	return false
}

