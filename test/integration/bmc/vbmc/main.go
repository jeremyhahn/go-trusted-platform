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

// vbmc is a minimal virtual BMC responder used by the devcontainer
// integration test harness. It speaks the subset of Redfish and
// Supermicro ATEN CGI endpoints that the platform's cert-management
// code exercises:
//
//   - /redfish/v1/                                         (vendor probe)
//
//   - /redfish/v1/Managers                                 (collection)
//
//   - /redfish/v1/Managers/1                               (manager resource)
//
//   - /redfish/v1/Managers/1/Actions/Manager.Reset         (reset)
//
//   - /redfish/v1/CertificateService/Actions/
//     CertificateService.ReplaceCertificate            (cert replace)
//
//   - /redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1
//     (factory cert restore via DELETE)
//
//   - /cgi/login.cgi                                       (session open)
//
//   - /cgi/upload_ssl.cgi                                  (cert+key upload)
//
//   - /cgi/op.cgi (op=SSL_VALIDATE)                        (validate)
//
//   - /cgi/BMC_reset.cgi                                   (reset)
//
//   - /cgi/logout.cgi                                      (session close)
//
// On startup, vbmc generates a self-signed ECDSA P-256 cert and serves
// it on its HTTPS listener. When a replacement cert is uploaded via
// either Redfish CertificateService or SMC CGI upload_ssl, the new
// cert+key are installed via an atomic handle so subsequent TLS
// handshakes present the new certificate.
//
// Vendor flavor (Supermicro vs Dell) is selected via the VBMC_VENDOR
// environment variable, which drives the /redfish/v1/ Vendor + Oem
// fields so platformd's AutoCertManager vendor probe resolves the
// expected branch.
//
// A plain HTTP listener on VBMC_CA_ADDR (default :8445) serves
// GET /tls/ca returning the PEM of the initial self-signed certificate.
// Clients use this endpoint to obtain a trust anchor and verify the
// HTTPS connection without InsecureSkipVerify.
//
// NOT in scope: full IPMI 2.0 RMCP+ responder. A later follow-up will
// either productionize the rmcpsim package into a reusable package or
// ship a standalone IPMI responder binary.
//
// Operator / test harness entry points:
//
//	env VBMC_VENDOR=Supermicro VBMC_HTTPS_ADDR=:8443 VBMC_CA_ADDR=:8445 ./vbmc
//
// Health check:
//
//	curl -sk https://vbmc:8443/healthz    -> 200 "ok"
//
// CA cert retrieval (plain HTTP):
//
//	curl http://vbmc:8445/tls/ca          -> PEM certificate
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/bmc/rmcpsim"
)

// config captures the vBMC runtime settings, pulled from env vars at
// startup so the binary is trivially configurable in the devcontainer
// docker-compose service.
type config struct {
	httpsAddr    string // e.g., ":8443"
	caAddr       string // e.g., ":8445" — plain HTTP for CA cert retrieval
	vendor       string // "Supermicro" | "Dell" | "Generic"
	cn           string // self-signed cert CN
	logLevel     slog.Level
	ipmiAddr     string // e.g., ":6230"
	ipmiUser     string // IPMI account the simulator accepts
	ipmiPassword string // IPMI account password
}

func loadConfig() config {
	c := config{
		httpsAddr:    getenv("VBMC_HTTPS_ADDR", ":8443"),
		caAddr:       getenv("VBMC_CA_ADDR", ":8445"),
		vendor:       getenv("VBMC_VENDOR", "Supermicro"),
		cn:           getenv("VBMC_CN", "vbmc.example.internal"),
		ipmiAddr:     getenv("VBMC_IPMI_ADDR", ":6230"),
		ipmiUser:     getenv("VBMC_IPMI_USER", "ADMIN"),
		ipmiPassword: getenv("VBMC_IPMI_PASSWORD", "ADMIN"),
	}
	switch strings.ToLower(os.Getenv("VBMC_LOG_LEVEL")) {
	case "debug":
		c.logLevel = slog.LevelDebug
	case "warn":
		c.logLevel = slog.LevelWarn
	case "error":
		c.logLevel = slog.LevelError
	default:
		c.logLevel = slog.LevelInfo
	}
	return c
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// certHolder wraps an atomic.Value so the HTTPS server reads the
// currently-installed certificate lock-free on each handshake, while
// replace operations atomically swap in a new one.
type certHolder struct {
	current atomic.Value // *tls.Certificate
}

func (h *certHolder) get() *tls.Certificate {
	v := h.current.Load()
	if v == nil {
		return nil
	}
	return v.(*tls.Certificate)
}

func (h *certHolder) replace(c *tls.Certificate) {
	h.current.Store(c)
}

// generateSelfSignedCert builds a short-lived self-signed ECDSA P-256
// cert used on startup before any replacement has been uploaded.
// It returns the tls.Certificate and the PEM encoding of the certificate
// (the trust anchor callers use to verify HTTPS connections).
func generateSelfSignedCert(cn string) (*tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{cn},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, certPEM, nil
}

// generateRestoredCert builds a fresh ECDSA certificate for the factory restore
// ceremony. It is signed by the same private key as the initial factory cert
// (factoryCert) but uses factoryCert as the issuer parent so the resulting cert
// is NOT self-signed (Issuer != Subject). This is critical for TLS verification:
// Go's x509 library refuses to verify a self-signed cert via chain — it requires
// the cert to be directly in the root pool. By making the restored cert a leaf
// signed by factoryCert-as-CA, any TLS client whose RootCAs pool contains
// factoryCert can verify the restored cert without InsecureSkipVerify.
func generateRestoredCert(factoryCert *x509.Certificate, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cn := factoryCert.Subject.CommonName
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// Use a distinct Subject so the cert is not self-signed.
		// TLS hostname verification uses IP/DNS SANs, not the Subject CN,
		// so clients connecting to 127.0.0.1 are unaffected by the different CN.
		Subject:               pkix.Name{CommonName: cn + "-restored"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{cn},
		IPAddresses:           factoryCert.IPAddresses,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// factoryCert is the parent/issuer: tmpl.Issuer = factoryCert.Subject.
	// The signature is produced by key (same as factoryCert's private key).
	der, err := x509.CreateCertificate(rand.Reader, tmpl, factoryCert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

// sessionStore tracks active SMC CGI sessions keyed by SID cookie.
// Small, in-memory, no expiry -- integration tests create short-lived
// sessions only.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}}
}

func (s *sessionStore) open() string {
	sid := randomToken(16)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sid] = time.Now()
	return sid
}

func (s *sessionStore) valid(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[sid]
	return ok
}

func (s *sessionStore) close(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
}

// randomToken returns a hex-encoded cryptographically random token of
// the given byte length.
func randomToken(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// vbmcServer bundles the mutable state a single vBMC instance tracks.
type vbmcServer struct {
	cfg      config
	logger   *slog.Logger
	certs    *certHolder
	sessions *sessionStore

	// factoryKey is the ECDSA private key used to generate the initial
	// self-signed certificate. The restore handler reuses this key to
	// sign the restored certificate.
	factoryKey *ecdsa.PrivateKey

	// factoryCert is the parsed x509.Certificate from the initial self-signed
	// cert. The restore handler uses it as the issuer parent when generating
	// the restored leaf cert so the leaf is NOT self-signed (Issuer != Subject),
	// which is required for Go's x509 chain verification via the RootCAs pool.
	factoryCert *x509.Certificate

	// initialCertPEM holds the PEM of the self-signed cert generated at
	// startup. It is served by the plain HTTP /tls/ca endpoint so clients
	// can build a verified TLS trust anchor without InsecureSkipVerify.
	initialCertPEM []byte

	// replaceCount tracks cert replacement operations for audit /
	// test assertions. Read via GET /debug/stats.
	replaceCount atomic.Uint64
	resetCount   atomic.Uint64
}

func newVBMC(cfg config, logger *slog.Logger, initial *tls.Certificate, initialCertPEM []byte, factoryKey *ecdsa.PrivateKey, factoryCert *x509.Certificate) *vbmcServer {
	s := &vbmcServer{
		cfg:            cfg,
		logger:         logger,
		certs:          &certHolder{},
		sessions:       newSessionStore(),
		factoryKey:     factoryKey,
		factoryCert:    factoryCert,
		initialCertPEM: initialCertPEM,
	}
	s.certs.replace(initial)
	return s
}

// routes wires the HTTP mux for the HTTPS server.
func (s *vbmcServer) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health + debug
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/debug/stats", s.handleDebugStats)

	// Redfish
	mux.HandleFunc("/redfish/v1/", s.handleRedfishRoot)
	mux.HandleFunc("/redfish/v1/Managers", s.handleRedfishManagers)
	mux.HandleFunc("/redfish/v1/Managers/1", s.handleRedfishManager1)
	mux.HandleFunc("/redfish/v1/Systems", s.handleRedfishSystems)
	mux.HandleFunc("/redfish/v1/Systems/1", s.handleRedfishSystem1)
	mux.HandleFunc("/redfish/v1/Chassis", s.handleRedfishChassisCollection)
	mux.HandleFunc("/redfish/v1/Chassis/1", s.handleRedfishChassis1)
	mux.HandleFunc("/redfish/v1/Managers/1/Actions/Manager.Reset", s.handleRedfishReset)
	mux.HandleFunc("/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate", s.handleRedfishReplaceCert)
	mux.HandleFunc("/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1", s.handleRedfishDeleteCert)

	// Supermicro CGI
	mux.HandleFunc("/cgi/login.cgi", s.handleCGILogin)
	mux.HandleFunc("/cgi/upload_ssl.cgi", s.handleCGIUploadSSL)
	mux.HandleFunc("/cgi/op.cgi", s.handleCGIOp)
	mux.HandleFunc("/cgi/BMC_reset.cgi", s.handleCGIReset)
	mux.HandleFunc("/cgi/logout.cgi", s.handleCGILogout)

	return mux
}

// caRoutes wires the plain HTTP mux for the CA trust-bootstrap server.
// This separate listener exposes only the /tls/ca endpoint so harness
// clients can retrieve the initial self-signed certificate PEM and build
// a verified TLS trust anchor — no InsecureSkipVerify required.
func (s *vbmcServer) caRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/tls/ca", s.handleTLSCA)
	return mux
}

// handleTLSCA serves the PEM of the initial self-signed certificate over
// plain HTTP. Clients use this to bootstrap TLS trust before connecting
// to the HTTPS endpoints.
func (s *vbmcServer) handleTLSCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.initialCertPEM)
}

// --- health / debug ---

func (s *vbmcServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *vbmcServer) handleDebugStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"vendor":          s.cfg.vendor,
		"cert_replace":    s.replaceCount.Load(),
		"reset":           s.resetCount.Load(),
		"active_sessions": len(s.sessions.sessions),
	})
}

// --- Redfish ---

func (s *vbmcServer) handleRedfishRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/redfish/v1/" && r.URL.Path != "/redfish/v1" {
		http.NotFound(w, r)
		return
	}
	body := map[string]any{
		"@odata.id":      "/redfish/v1/",
		"RedfishVersion": "1.6.0",
		"Vendor":         s.cfg.vendor,
		"Managers":       map[string]any{"@odata.id": "/redfish/v1/Managers"},
		"Systems":        map[string]any{"@odata.id": "/redfish/v1/Systems"},
		"Chassis":        map[string]any{"@odata.id": "/redfish/v1/Chassis"},
	}
	if strings.EqualFold(s.cfg.vendor, "Supermicro") {
		body["Oem"] = map[string]any{"Supermicro": map[string]any{}}
	} else if strings.EqualFold(s.cfg.vendor, "Dell") {
		body["Oem"] = map[string]any{"Dell": map[string]any{}}
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *vbmcServer) handleRedfishManagers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Managers",
		"Members": []map[string]any{
			{"@odata.id": "/redfish/v1/Managers/1"},
		},
	})
}

func (s *vbmcServer) handleRedfishManager1(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Managers/1",
		"Id":        "1",
		"Actions": map[string]any{
			"#Manager.Reset": map[string]any{
				"target": "/redfish/v1/Managers/1/Actions/Manager.Reset",
			},
		},
	})
}

// hardwareIdentity is the identity a real BMC serves on its System and
// Chassis resources. pkg/quirks resolves board quirks from it.
type hardwareIdentity struct {
	Manufacturer string
	Model        string
	PartNumber   string
	SerialNumber string
	SKU          string
}

// vendorIdentities maps the (lower-cased) --vendor value to the identity the
// fixture serves. Supermicro matches the pkg/quirks X10SDV entry and Dell the
// manufacturer-wide "Dell Inc." entry, so each variant resolves to a distinct
// quirk.
var vendorIdentities = map[string]hardwareIdentity{
	"supermicro": {
		Manufacturer: "Supermicro",
		Model:        "X10SDV-TP8F",
		PartNumber:   "SYS-5018D-FN8T-AS001",
		SerialNumber: "VBMC-SMC-0001",
		SKU:          "SYS-5018D-FN8T",
	},
	"dell": {
		Manufacturer: "Dell Inc.",
		Model:        "PowerEdge R650",
		PartNumber:   "0X3D66A00",
		SerialNumber: "VBMC-DELL-0001",
		SKU:          "R650-VBMC",
	},
}

// identity returns the hardware identity for the configured vendor. Any other
// vendor string is served as its own manufacturer, so a custom --vendor still
// answers with a complete, self-describing identity.
func (s *vbmcServer) identity() hardwareIdentity {
	if id, ok := vendorIdentities[strings.ToLower(s.cfg.vendor)]; ok {
		return id
	}
	return hardwareIdentity{
		Manufacturer: s.cfg.vendor,
		Model:        "Virtual BMC",
		PartNumber:   "VBMC-GENERIC",
		SerialNumber: "VBMC-GENERIC-0001",
		SKU:          "VBMC-GENERIC",
	}
}

// identityBody renders the identity fields shared by System and Chassis.
func (s *vbmcServer) identityBody(odataID string) map[string]any {
	id := s.identity()
	return map[string]any{
		"@odata.id":    odataID,
		"Id":           "1",
		"Manufacturer": id.Manufacturer,
		"Model":        id.Model,
		"PartNumber":   id.PartNumber,
		"SerialNumber": id.SerialNumber,
		"SKU":          id.SKU,
	}
}

func (s *vbmcServer) handleRedfishSystems(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Systems",
		"Members": []map[string]any{
			{"@odata.id": "/redfish/v1/Systems/1"},
		},
	})
}

func (s *vbmcServer) handleRedfishSystem1(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.identityBody("/redfish/v1/Systems/1"))
}

func (s *vbmcServer) handleRedfishChassisCollection(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Chassis",
		"Members": []map[string]any{
			{"@odata.id": "/redfish/v1/Chassis/1"},
		},
	})
}

func (s *vbmcServer) handleRedfishChassis1(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.identityBody("/redfish/v1/Chassis/1"))
}

func (s *vbmcServer) handleRedfishReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.resetCount.Add(1)
	s.logger.Info("vbmc: Redfish Manager.Reset invoked")
	w.WriteHeader(http.StatusNoContent)
}

// handleRedfishDeleteCert handles DELETE /redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1.
// Per DMTF Redfish §Certificates, deleting the active HTTPS certificate causes the
// BMC to fall back to a freshly generated self-signed default certificate on the
// next web-server restart. The vBMC simulates this by immediately regenerating a
// new self-signed cert using the original factory private key so the same-key
// trust chain allows callers to verify the restored cert.
func (s *vbmcServer) handleRedfishDeleteCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	newCert, err := generateRestoredCert(s.factoryCert, s.factoryKey)
	if err != nil {
		s.logger.Error("vbmc: factory cert regeneration failed", "err", err)
		http.Error(w, "cert regeneration failed", http.StatusInternalServerError)
		return
	}
	s.certs.replace(newCert)
	s.replaceCount.Add(1)
	s.logger.Info("vbmc: factory cert restored (Redfish DELETE cert)")
	w.WriteHeader(http.StatusNoContent)
}

// redfishReplaceCertBody matches the CertificateService schema
// subset platformd sends.
type redfishReplaceCertBody struct {
	CertificateString string `json:"CertificateString"`
	CertificateType   string `json:"CertificateType"`
	CertificateURI    struct {
		ODataID string `json:"@odata.id"`
	} `json:"CertificateUri"`
}

func (s *vbmcServer) handleRedfishReplaceCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body redfishReplaceCertBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.CertificateString == "" {
		http.Error(w, "empty CertificateString", http.StatusBadRequest)
		return
	}
	if err := s.installCertBundle([]byte(body.CertificateString), "redfish"); err != nil {
		s.logger.Error("vbmc: cert install failed", "path", "redfish", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Supermicro CGI ---

func (s *vbmcServer) handleCGILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	// Accept any credentials -- this is a test BMC, not a security
	// boundary. Real hardware auth is out of scope for integration
	// test infrastructure.
	sid := s.sessions.open()
	http.SetCookie(w, &http.Cookie{Name: "SID", Value: sid, Path: "/", HttpOnly: true})
	_, _ = io.WriteString(w, "ok")
}

func (s *vbmcServer) handleCGIUploadSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cookieValid(r) {
		http.Error(w, "no valid SID", http.StatusUnauthorized)
		return
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "invalid content type", http.StatusBadRequest)
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])

	var certPEM, keyPEM []byte
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "multipart read: "+err.Error(), http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			http.Error(w, "read part: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "cert_file":
			certPEM = data
		case "key_file":
			keyPEM = data
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		http.Error(w, "missing cert_file or key_file", http.StatusBadRequest)
		return
	}
	if err := s.installCertKeyPEM(certPEM, keyPEM, "smc-cgi"); err != nil {
		s.logger.Error("vbmc: cert install failed", "path", "smc-cgi", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, "<html>upload complete</html>")
}

func (s *vbmcServer) handleCGIOp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	if !s.cookieValid(r) {
		http.Error(w, "no valid SID", http.StatusUnauthorized)
		return
	}
	if r.Form.Get("op") == "SSL_VALIDATE" {
		_, _ = io.WriteString(w, `{"VALID":"1"}`)
		return
	}
	http.Error(w, "unsupported op", http.StatusBadRequest)
}

func (s *vbmcServer) handleCGIReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cookieValid(r) {
		http.Error(w, "no valid SID", http.StatusUnauthorized)
		return
	}
	s.resetCount.Add(1)
	s.logger.Info("vbmc: CGI BMC_reset invoked")
	w.WriteHeader(http.StatusOK)
}

func (s *vbmcServer) handleCGILogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("SID"); err == nil {
		s.sessions.close(c.Value)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *vbmcServer) cookieValid(r *http.Request) bool {
	c, err := r.Cookie("SID")
	if err != nil {
		return false
	}
	return s.sessions.valid(c.Value)
}

// --- cert installation ---

// installCertBundle parses a PEM bundle containing a private key and
// one or more certificates (Redfish CertificateService format) and
// atomically installs it as the new TLS identity.
func (s *vbmcServer) installCertBundle(bundle []byte, path string) error {
	var certDER [][]byte
	var keyDER []byte
	rest := bundle
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certDER = append(certDER, block.Bytes)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			keyDER = block.Bytes
		}
		rest = next
	}
	if len(certDER) == 0 {
		return errors.New("no certificate in bundle")
	}
	if len(keyDER) == 0 {
		return errors.New("no private key in bundle")
	}
	priv, err := parsePrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	tlsCert := &tls.Certificate{Certificate: certDER, PrivateKey: priv}
	s.certs.replace(tlsCert)
	s.replaceCount.Add(1)
	s.logger.Info("vbmc: cert installed", "path", path)
	return nil
}

// installCertKeyPEM installs a cert+key pair supplied as two
// separate PEM blobs (SMC CGI multipart format).
func (s *vbmcServer) installCertKeyPEM(certPEM, keyPEM []byte, path string) error {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("X509KeyPair: %w", err)
	}
	s.certs.replace(&tlsCert)
	s.replaceCount.Add(1)
	s.logger.Info("vbmc: cert installed", "path", path)
	return nil
}

// parsePrivateKey handles PKCS8, EC, and RSA private key DERs.
func parsePrivateKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

// --- HTTP plumbing ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- main ---

// main is a thin wrapper so every failure path leaves through run's
// returns: os.Exit skips deferred calls, and run owns the signal context
// and the shutdown timeout that must be released on the way out.
func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg := loadConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))

	initial, certPEM, err := generateSelfSignedCert(cfg.cn)
	if err != nil {
		logger.Error("vbmc: self-signed cert generation failed", "err", err)
		return err
	}

	factoryKey := initial.PrivateKey.(*ecdsa.PrivateKey)
	factoryCert, err := x509.ParseCertificate(initial.Certificate[0])
	if err != nil {
		logger.Error("vbmc: failed to parse initial factory cert", "err", err)
		return err
	}
	server := newVBMC(cfg, logger, initial, certPEM, factoryKey, factoryCert)

	tlsConfig := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := server.certs.get()
			if c == nil {
				return nil, errors.New("vbmc: no certificate installed")
			}
			return c, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	srv := &http.Server{
		Addr:              cfg.httpsAddr,
		Handler:           server.routes(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Plain HTTP server exposing GET /tls/ca so harness clients can
	// retrieve the initial self-signed certificate PEM and build a
	// verified TLS trust anchor without InsecureSkipVerify.
	caSrv := &http.Server{
		Addr:              cfg.caAddr,
		Handler:           server.caRoutes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// IPMI 2.0 RMCP+ simulator. Provides a real UDP IPMI surface
	// alongside the HTTPS Redfish / SMC CGI endpoints so integration
	// tests can exercise ipmitool-equivalent flows against the vBMC.
	sim, err := rmcpsim.New(rmcpsim.Options{
		Addr:     cfg.ipmiAddr,
		Username: cfg.ipmiUser,
		Password: cfg.ipmiPassword,
		Logger:   logger,
	})
	if err != nil {
		logger.Error("vbmc: rmcpsim construction failed", "err", err)
		return err
	}
	if err := sim.Start(); err != nil {
		logger.Error("vbmc: rmcpsim start failed", "addr", cfg.ipmiAddr, "err", err)
		return err
	}
	logger.Info("vbmc: IPMI simulator listening", "addr", sim.LocalAddr().String(), "user", cfg.ipmiUser)

	go func() {
		logger.Info("vbmc: CA endpoint listening", "addr", cfg.caAddr)
		if err := caSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("vbmc: CA server error", "err", err)
			cancel()
		}
	}()

	go func() {
		logger.Info("vbmc: listening", "addr", cfg.httpsAddr, "vendor", cfg.vendor)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("vbmc: serve error", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("vbmc: shutting down")
	sim.Stop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = caSrv.Shutdown(shutdownCtx)
	return nil
}
