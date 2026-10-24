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

package ipxe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// DeviceLookup is a callback that resolves a MAC address to boot info.
// This is called by the HTTP server when a device-specific boot script is requested.
type DeviceLookup func(mac string) (*DeviceBootInfo, error)

// HTTPServer represents an HTTP server for iPXE scripts and boot files.
type HTTPServer struct {
	config       *ServerConfig
	logger       *logging.Logger
	server       *http.Server
	deviceLookup DeviceLookup
	scriptGen    *ScriptGenerator

	// procRootOverride replaces /proc for the /media/status scan. Empty
	// in production; tests point it at a fabricated proc tree.
	procRootOverride string

	// mediaWatcher is the sampler behind /media/status, started by Start
	// when DataDir is set; nil until then.
	mediaWatcher atomic.Pointer[mediaWatcher]
}

// NewHTTPServer creates a new HTTP server instance.
func NewHTTPServer(cfg *ServerConfig, logger *logging.Logger) *HTTPServer {
	return &HTTPServer{
		config: cfg,
		logger: logger,
	}
}

// SetDeviceLookup configures the device lookup callback and script generator
// for per-device boot script generation. When set, the /boot/device/{mac}.ipxe
// route is registered.
func (s *HTTPServer) SetDeviceLookup(lookup DeviceLookup, gen *ScriptGenerator) {
	s.deviceLookup = lookup
	s.scriptGen = gen
}

// Start begins the HTTP server with graceful shutdown support.
func (s *HTTPServer) Start(ctx context.Context, bound chan<- struct{}) error {
	mux := http.NewServeMux()

	// Main iPXE boot script
	mux.HandleFunc("/boot.ipxe", s.handleBootScript)

	// Boot menu
	mux.HandleFunc("/menu.ipxe", s.handleMenuScript)

	// Per-device boot scripts (when device lookup is configured)
	if s.deviceLookup != nil && s.scriptGen != nil {
		mux.HandleFunc("/boot/device/", s.handleDeviceBootScript)
	}

	// Individual boot entries
	mux.HandleFunc("/boot/", s.handleBootEntry)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Static files (for custom configs)
	mux.HandleFunc("/static/", s.handleStatic)

	// Local files endpoint (for serving kernel/initrd from local disk)
	if s.config.LocalFilesDir != "" {
		mux.HandleFunc("/files/", s.handleLocalFiles)
	}

	// /data/ endpoint serves the container's bind-mounted data
	// directory (vmlinuz, initramfs, ISOs, ...). The bootstrap.ipxe
	// boot-entry script references kernel/initrd as `/data/<file>`
	// so iPXE fetches them from this URL prefix on the same HTTP
	// server. Without this handler, the iPXE chainload succeeds
	// but kernel/initrd fetches 404 — the iPXE shell drops out
	// with "Could not boot: Not found".
	if s.config.DataDir != "" {
		mux.HandleFunc("/data/", s.handleDataFiles)
	}

	// Media-read evidence for the orchestrator's virtual-media boot:
	// which files under DataDir have been open (by smbd, for the BMC)
	// and how far they were read, sampled continuously. Registered
	// unconditionally so a client can tell "no data dir" (503) from
	// "old container" (404).
	mux.HandleFunc("/media/status", s.handleMediaStatus)

	// Proxy endpoint for HTTPS resources (iPXE doesn't support HTTPS)
	mux.HandleFunc("/proxy/", s.handleProxy)

	// Forensic install-log sink. PUT /installs/{hostname}/{filename} writes
	// a file under <data-dir>/installs/{hostname}/. GET /installs/ returns
	// an HTML index for browsing. Used by autoinstall.sh to upload
	// /tmp/install.log on both success and failure paths so we always have
	// post-mortem data after the install env reboots.
	mux.HandleFunc("/installs/", s.handleInstalls)

	// Per-MAC config delivery. PUT /config/mac/{mac}/{key} stores a small
	// plain-text value indexed by MAC; GET returns the value. Used by
	// autoinstall.sh to fetch per-node overrides (hostname first and
	// foremost) that the orchestrator stages before booting the ISO.
	// Without this, the shared ISO bakes a generic hostname ("server")
	// into every node. Each node's autoinstall queries
	// /config/mac/<its-primary-mac>/hostname and replaces the baked value
	// when a match is found.
	mux.HandleFunc("/config/", s.handleConfig)

	addr := s.config.listenAddr(s.config.HTTPPort)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Bind BEFORE serving, so a bind failure is synchronous and a
	// successful bind can be signalled. ListenAndServe hides both
	// inside one blocking call, which is why a port conflict here used
	// to surface only as an async error while callers had already moved
	// on.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return &WrappedError{Msg: "HTTP server failed to bind " + addr, Err: err}
	}

	// The media watcher's goroutine lives exactly as long as the bound
	// server does, so it starts after the bind, not before: a bind
	// failure returns with nothing left running.
	s.startMediaWatcher(ctx)

	s.logger.Info("HTTP server starting", "address", addr)
	signalBound(bound)

	errChan := make(chan error, 1)
	go func() {
		errChan <- s.server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logger.Info("HTTP server shutting down")
		shutdownErr := s.server.Shutdown(shutdownCtx)
		// Shutdown closes only the listeners Serve has tracked. When the
		// cancel lands before Serve has tracked ln, Serve's own deferred
		// Close releases the port, so Start returns only after Serve has.
		// A restart on the same port would otherwise race that Close.
		serveErr := <-errChan
		if shutdownErr != nil {
			return shutdownErr
		}
		if serveErr != http.ErrServerClosed {
			return &WrappedError{Msg: "HTTP server failed", Err: serveErr}
		}
		return nil
	case err := <-errChan:
		if err == http.ErrServerClosed {
			return nil
		}
		return &WrappedError{Msg: "HTTP server failed", Err: err}
	}
}

// loggingMiddleware wraps handlers with request logging.
func (s *HTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleBootScript serves the initial boot script.
//
// When exactly one BootEntry is configured (the common bootstrap-
// container case) the script inlines the kernel + initrd + args
// directly so iPXE only needs one HTTP fetch to start the boot.
// This avoids the boot.ipxe → menu.ipxe → bootstrap.ipxe chain
// pattern, which on some BIOS+iPXE combinations (observed on
// Supermicro X10 + Intel Boot Agent GE 1.5.13 + iPXE 2.0.0+) times
// out on the second chained HTTP request even though the first
// fetch from the same server succeeds. Inlining produces a single
// successful HTTP exchange that the X10 firmware does not drop.
//
// When zero or more than one BootEntry is configured the script
// falls back to the menu-based flow so operators with multi-image
// setups still get an interactive selection.
func (s *HTTPServer) handleBootScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var sb strings.Builder
	sb.WriteString("#!ipxe\n")

	// A known device boots what it was assigned; the per-device route
	// answers 404 for any other MAC and the chain falls through to the
	// entries below. ${mac:hexhyp} is the booting NIC's MAC, dashed.
	if s.deviceLookup != nil {
		sb.WriteString("chain --autofree boot/device/${mac:hexhyp}.ipxe ||\n")
	}

	switch entries := s.config.BootEntries; {
	case len(entries) == 1 && entries[0].Kernel != "" && entries[0].Initrd != "":
		entry := entries[0]
		sb.WriteString(architectureGuard(entry.Architecture, "menu.ipxe"))
		sb.WriteString(bootBlock("", entry.Description, s.proxyURL(entry.Kernel), s.proxyArgsURLs(entry.Args), s.proxyURL(entry.Initrd)))
	case distinctArchitectures(entries):
		// One entry per architecture (the bootstrap container's media
		// sets): boot the client's own, unattended.
		for _, entry := range entries {
			for _, client := range dispatchArchitectures(entry.Architecture, entries) {
				fmt.Fprintf(&sb, "iseq ${buildarch} %s && goto arch_%s ||\n", client, entry.Architecture)
			}
		}
		sb.WriteString("chain menu.ipxe?arch=${buildarch} || shell\n")
		for _, entry := range entries {
			fmt.Fprintf(&sb, ":arch_%s\n", entry.Architecture)
			sb.WriteString(bootBlock(entry.Architecture, entry.Description, s.proxyURL(entry.Kernel), s.proxyArgsURLs(entry.Args), s.proxyURL(entry.Initrd)))
		}
	default:
		sb.WriteString("echo Booting from PXE server...\nchain menu.ipxe?arch=${buildarch} || shell\n")
	}
	if _, err := w.Write([]byte(sb.String())); err != nil {
		s.logger.Warn("writing boot script", "error", err.Error())
	}
}

// dispatchArchitectures is ClientArchitectures less any architecture
// another entry claims for itself (an explicit i386 entry wins i386).
func dispatchArchitectures(architecture string, entries []BootEntry) []string {
	var out []string
	for _, client := range ClientArchitectures(architecture) {
		claimed := false
		for _, e := range entries {
			if e.Architecture == client && client != architecture {
				claimed = true
			}
		}
		if !claimed {
			out = append(out, client)
		}
	}
	return out
}

// distinctArchitectures reports whether entries can be dispatched by
// architecture alone: more than one, each with a kernel, an initrd and an
// architecture no other entry has.
func distinctArchitectures(entries []BootEntry) bool {
	if len(entries) < 2 {
		return false
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Architecture == "" || e.Kernel == "" || e.Initrd == "" || seen[e.Architecture] {
			return false
		}
		seen[e.Architecture] = true
	}
	return true
}

// handleMenuScript serves the dynamic boot menu with all configured entries.
func (s *HTTPServer) handleMenuScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	tmpl := `#!ipxe

# Boot menu
menu PXE Boot Menu
item --gap --             ------------------------- Boot Options --------------------------
{{range .Entries}}
item {{.Name}}            {{.Description}}
{{end}}
item --gap --             ------------------------- Utilities -----------------------------
item shell                Drop to iPXE shell
item reboot               Reboot system
item exit                 Exit to BIOS

choose --timeout 30000 --default {{.Default}} selected || goto exit
goto ${selected}

{{range .Entries}}
:{{.Name}}
echo Booting {{.Description}}...
chain {{$.BaseURL}}/boot/{{.Name}}.ipxe || goto failed
goto end
{{end}}

:shell
echo Type 'exit' to return to menu
shell
goto start

:reboot
reboot

:exit
exit

:failed
echo Boot failed, dropping to shell
shell

:end
`

	// ?arch=<iPXE buildarch> narrows the menu to what this client can run.
	entries := EntriesForArchitecture(s.config.BootEntries, r.URL.Query().Get("arch"))
	data := struct {
		Entries []BootEntry
		Default string
		BaseURL string
	}{
		Entries: entries,
		Default: "",
		BaseURL: s.config.ExternalURL,
	}

	if len(entries) > 0 {
		data.Default = entries[0].Name
	}

	t, err := template.New("menu").Parse(tmpl)
	if err != nil {
		s.logger.Errorf("failed to parse menu template: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, data); err != nil {
		s.logger.Errorf("failed to execute menu template: %v", err)
	}
}

// handleBootEntry serves per-entry boot scripts.
func (s *HTTPServer) handleBootEntry(w http.ResponseWriter, r *http.Request) {
	// Extract entry name from path
	path := strings.TrimPrefix(r.URL.Path, "/boot/")
	name := strings.TrimSuffix(path, ".ipxe")

	var entry *BootEntry
	for _, e := range s.config.BootEntries {
		if e.Name == name {
			entry = &e
			break
		}
	}

	if entry == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")

	// Generate boot script based on entry type
	var script string

	switch {
	case entry.ISOURL != "":
		// For Alpine and similar distros that support network boot
		script = s.generateNetbootScript(entry)
	case entry.Kernel != "":
		// Direct kernel boot
		script = s.generateKernelScript(entry)
	default:
		http.Error(w, "Invalid boot entry configuration", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(script))
}

// handleDeviceBootScript serves per-device iPXE boot scripts based on MAC address.
// Route: /boot/device/{mac}.ipxe
func (s *HTTPServer) handleDeviceBootScript(w http.ResponseWriter, r *http.Request) {
	// Extract MAC from path: /boot/device/52:54:00:aa:bb:cc.ipxe
	path := strings.TrimPrefix(r.URL.Path, "/boot/device/")
	mac := strings.TrimSuffix(path, ".ipxe")

	if mac == "" {
		http.Error(w, "missing MAC address", http.StatusBadRequest)
		return
	}

	// Normalize MAC: accept dashes or colons, lowercase
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	info, err := s.deviceLookup(mac)
	switch {
	case errors.Is(err, ErrDeviceNotFound):
		s.logger.Debug("no per-device assignment; client falls through to the default entries", "mac", mac)
		http.Error(w, "device not found", http.StatusNotFound)
		return
	case err != nil:
		s.logger.Warn("device lookup failed", "mac", mac, "error", err.Error())
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}

	script := s.scriptGen.GenerateScript(info)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(script))
}

// handleHealth serves a health check endpoint.
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy"}`))
}

// handleStatic serves static files from the ./static directory.
func (s *HTTPServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Serve static files from ./static directory
	path := strings.TrimPrefix(r.URL.Path, "/static/")

	// Prevent directory traversal
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	http.ServeFile(w, r, filepath.Join(".", "static", path))
}

// handleLocalFiles serves files from the configured LocalFilesDir.
func (s *HTTPServer) handleLocalFiles(w http.ResponseWriter, r *http.Request) {
	if s.config.LocalFilesDir == "" {
		http.NotFound(w, r)
		return
	}

	// Extract filename from path
	filename := strings.TrimPrefix(r.URL.Path, "/files/")
	if filename == "" || strings.Contains(filename, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Construct full path
	fullPath := filepath.Join(s.config.LocalFilesDir, filename)

	// Check if file exists
	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		s.logger.Warn("local file not found", "path", fullPath)
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.logger.Errorf("error accessing local file %s: %v", fullPath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Don't serve directories
	if info.IsDir() {
		http.Error(w, "Cannot serve directories", http.StatusForbidden)
		return
	}

	s.logger.Info("serving local file", "file", filename, "size", info.Size())

	// Serve the file
	http.ServeFile(w, r, fullPath)
}

// handleDataFiles serves files from the configured DataDir under the
// /data/ URL prefix. Used by the iPXE bootstrap script to fetch
// kernel and initrd images that the container has staged on its
// bind-mounted /data volume.
//
// Path traversal is rejected (any ".." segment aborts the request),
// directory listings are denied, and missing files return 404 with
// a logged warning so the operator can diagnose mis-staged content.
//
// Symlinks INSIDE DataDir are followed via http.ServeFile, which is
// consistent with handleLocalFiles. DataDir itself is expected to be
// owned by the operator; this handler does not attempt to sandbox
// against an attacker who controls files inside it.
func (s *HTTPServer) handleDataFiles(w http.ResponseWriter, r *http.Request) {
	if s.config.DataDir == "" {
		http.NotFound(w, r)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/data/")
	if filename == "" || strings.Contains(filename, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(s.config.DataDir, filename)

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		s.logger.Warn("data file not found", "path", fullPath)
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.logger.Errorf("error accessing data file %s: %v", fullPath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		http.Error(w, "Cannot serve directories", http.StatusForbidden)
		return
	}

	s.logger.Info("serving data file", "file", filename, "size", info.Size())
	http.ServeFile(w, r, fullPath)
}

// handleProxy proxies HTTPS requests for iPXE (which doesn't support HTTPS).
func (s *HTTPServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Extract the URL from the path: /proxy/https/host/path
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if path == "" {
		http.Error(w, "Missing URL", http.StatusBadRequest)
		return
	}

	// Reconstruct the URL: https/host/path -> https://host/path
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	scheme := parts[0]
	rest := parts[1]
	targetURL := fmt.Sprintf("%s://%s", scheme, rest)

	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		s.logger.Errorf("invalid proxy URL %s: %v", targetURL, err)
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Only allow https proxying
	if parsedURL.Scheme != "https" {
		http.Error(w, "Only HTTPS proxying is supported", http.StatusBadRequest)
		return
	}

	s.logger.Info("proxying request", "url", targetURL)

	// Create HTTP client with reasonable timeout for large files.
	// TLS verification is mandatory — use the configured CA pool or the
	// system certificate pool for upstream HTTPS connections.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if s.config.ProxyCACertPool != nil {
		tlsCfg.RootCAs = s.config.ProxyCACertPool
	}
	client := &http.Client{
		Timeout: 5 * time.Minute, // Large files like kernels/initrds
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	// Fetch the remote resource
	resp, err := client.Get(targetURL)
	if err != nil {
		s.logger.Errorf("proxy fetch failed for %s: %v", targetURL, err)
		http.Error(w, "Failed to fetch remote resource", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the response
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logger.Errorf("error streaming proxy response: %v", err)
	}
}

// generateNetbootScript generates a boot script for network boot scenarios.
func (s *HTTPServer) generateNetbootScript(entry *BootEntry) string {
	// For Alpine Linux network boot
	// Uses kernel and initrd directly from the network

	tmpl := `#!ipxe

echo Booting %s...
echo

# Set kernel and initrd URLs
set iso_url %s
set kernel_url %s
set initrd_url %s

echo Loading kernel...
kernel ${kernel_url} %s
echo Loading initrd...
initrd ${initrd_url}

echo
echo Starting boot...
boot || goto failed

:failed
echo
echo Boot failed!
echo Press any key to return to menu
prompt
chain menu.ipxe
`

	// Build kernel/initrd URLs from ISO URL base
	baseURL := strings.TrimSuffix(entry.ISOURL, ".iso")
	if strings.Contains(entry.ISOURL, "alpine") {
		// Alpine specific netboot URLs
		baseURL = strings.Replace(entry.ISOURL, "/releases/", "/netboot/", 1)
		baseURL = strings.Replace(baseURL, "-standard-", "-netboot-", 1)
		baseURL = strings.TrimSuffix(baseURL, ".iso")
	}

	kernelURL := fmt.Sprintf("%s/vmlinuz-lts", strings.TrimSuffix(baseURL, "-lts"))
	initrdURL := fmt.Sprintf("%s/initramfs-lts", strings.TrimSuffix(baseURL, "-lts"))

	// If custom kernel/initrd paths provided, use those
	if entry.Kernel != "" && strings.HasPrefix(entry.Kernel, "http") {
		kernelURL = entry.Kernel
	}
	if entry.Initrd != "" && strings.HasPrefix(entry.Initrd, "http") {
		initrdURL = entry.Initrd
	}

	// Convert HTTPS URLs to proxy URLs since iPXE doesn't support HTTPS
	kernelURL = s.proxyURL(kernelURL)
	initrdURL = s.proxyURL(initrdURL)

	// Default Alpine kernel args for network boot
	// Also proxy any HTTPS URLs in the args
	args := entry.Args
	if args == "" {
		args = fmt.Sprintf("alpine_repo=%s modloop=%s",
			s.proxyURL("https://dl-cdn.alpinelinux.org/alpine/v3.20/main"),
			s.proxyURL("https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/modloop-lts"))
	} else {
		// Proxy any HTTPS URLs in the provided args
		args = s.proxyArgsURLs(args)
	}

	return fmt.Sprintf(tmpl, entry.Description, entry.ISOURL, kernelURL, initrdURL, args)
}

// generateKernelScript generates a boot script for direct kernel boot.
func (s *HTTPServer) generateKernelScript(entry *BootEntry) string {
	tmpl := `#!ipxe

echo Booting %s...
echo

kernel %s %s
initrd %s
boot || goto failed

:failed
echo
echo Boot failed!
prompt
chain menu.ipxe
`
	// Convert HTTPS URLs to proxy URLs since iPXE doesn't support HTTPS
	kernelURL := s.proxyURL(entry.Kernel)
	initrdURL := s.proxyURL(entry.Initrd)

	// Proxy any HTTPS URLs in the args
	args := s.proxyArgsURLs(entry.Args)

	return fmt.Sprintf(tmpl, entry.Description, kernelURL, args, initrdURL)
}

// proxyURL converts an HTTPS URL to a proxy URL through our HTTP server.
func (s *HTTPServer) proxyURL(originalURL string) string {
	if !strings.HasPrefix(originalURL, "https://") {
		return originalURL
	}
	// Convert https://host/path to http://server:port/proxy/https/host/path
	stripped := strings.TrimPrefix(originalURL, "https://")
	return fmt.Sprintf("%s/proxy/https/%s", s.config.ExternalURL, stripped)
}

// maxInstallLogUploadBytes caps install-log uploads. 16 MiB is plenty for a
// verbose install transcript including dmesg tail and dracut output, and
// firmly limits memory consumed by a misbehaving uploader.
const maxInstallLogUploadBytes int64 = 16 * 1024 * 1024

// installPathRegexp validates the upload path after /installs/. Two shapes
// are accepted:
//
//	{hostname}/{filename}         — legacy hostname-keyed uploads.
//	mac/{mac}/{filename}          — MAC-keyed uploads (preferred).
//
// The MAC form exists because a shared ISO has no way to know the
// per-node hostname at boot, but every node knows its own MAC. The
// orchestrator polls both keys; the installer uploads to whichever it
// can determine. The literal "mac/" prefix makes the two shapes
// unambiguous so a hostname that happens to equal "mac" doesn't
// collide with the MAC-keyed namespace.
//
// Segment character set is restricted so a malicious uploader can't
// path-traverse out of InstallsDir. Leading hyphens are allowed on
// hostnames because some live envs (Alpine busybox) report hostname as
// "(none)" which gets normalised to "-none-" by the upload script's sed
// pass — rejecting that would silently lose the very uploads we need
// most for unconfigured first-boot postmortems.
//
// hostname: lowercase letters, digits, hyphens, dots — extended DNS label set
// mac:      lowercase hex digits and hyphens only (sanitizeMACForPath output)
// filename: lowercase letters, digits, dots, hyphens, underscores
//
// Path traversal is blocked separately by the explicit ".." check in
// handleInstallUpload, so the regex doesn't need to defend against that.
var installPathRegexp = regexp.MustCompile(`^([a-z0-9.\-]{1,254})/([a-z0-9][a-z0-9._\-]{0,254})$`)
var installMACPathRegexp = regexp.MustCompile(`^mac/([0-9a-f\-]{12,17})/([a-z0-9][a-z0-9._\-]{0,254})$`)

// installIndexEntry is one row of the uploads directory listing.
type installIndexEntry struct {
	// Name is the entry's filename, with a trailing slash on directories.
	Name string
}

// installIndexData is the model installIndexTemplate renders.
type installIndexData struct {
	// Path is the request path below /installs/.
	Path string

	// Entries are the directory's children, in readdir order.
	Entries []installIndexEntry
}

// installIndexTemplate renders the uploads directory listing.
//
// Every value interpolated here arrives from a request: Path is the tail of
// the URL, echoed back verbatim, and each Name is a filename an uploader
// chose. Building this page with fmt.Fprintf reflected the URL into the
// document unescaped — a GET of /installs/<script>... put attacker markup in
// the response — and put unescaped filenames into both an href and the link
// text, which is stored XSS for anything that reaches the upload endpoint.
//
// html/template is used rather than escaping by hand because the two
// interpolations of Name need *different* escaping: the href is a URL
// context and the link text is an HTML text context. Contextual
// auto-escaping applies each correctly; a single html.EscapeString over both
// would leave the href wrong.
var installIndexTemplate = template.Must(template.New("installIndex").Parse(
	`<!doctype html><html><head><meta charset="utf-8">` +
		`<title>/installs/{{.Path}}</title></head>` +
		`<body><h1>/installs/{{.Path}}</h1><ul>` +
		`{{if .Path}}<li><a href="../">..</a></li>{{end}}` +
		`{{range .Entries}}<li><a href="{{.Name}}">{{.Name}}</a></li>{{end}}` +
		`</ul></body></html>`))

// handleInstalls dispatches /installs/ requests:
//
//	PUT  /installs/{hostname}/{filename}  → write upload to InstallsDir
//	GET  /installs/                       → HTML index of all hosts
//	GET  /installs/{hostname}/            → HTML index of one host's logs
//	GET  /installs/{hostname}/{filename}  → serve the file (text/plain)
//
// This is the bootstrap container's central forensic sink. autoinstall.sh
// uploads /tmp/install.log via PUT on every install — success OR failure —
// before the live environment reboots, so we always have post-mortem data
// even when the install env is gone.
func (s *HTTPServer) handleInstalls(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.handleInstallUpload(w, r)
	case http.MethodGet:
		s.handleInstallIndex(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstallUpload writes an upload to InstallsDir/{hostname}/{filename}.
// The path is validated against installPathRegexp before any filesystem
// operation, the request body is size-capped, and the file is written via
// .partial + atomic rename so half-uploaded logs never appear in the index.
func (s *HTTPServer) handleInstallUpload(w http.ResponseWriter, r *http.Request) {
	relative := strings.TrimPrefix(r.URL.Path, "/installs/")
	if relative == "" || strings.Contains(relative, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Try MAC-keyed shape (mac/<mac>/<file>) first, then fall back to the
	// legacy hostname-keyed shape (<host>/<file>). Both land in the same
	// on-disk layout — InstallsDir/<key>/<filename> — so the GET handler
	// and index code need no changes.
	var hostname, filename string
	if m := installMACPathRegexp.FindStringSubmatch(relative); m != nil {
		hostname = "mac/" + m[1]
		filename = m[2]
	} else if m := installPathRegexp.FindStringSubmatch(relative); m != nil {
		hostname = m[1]
		filename = m[2]
	} else {
		http.Error(w, "path must be {hostname}/{filename} or mac/{mac}/{filename}", http.StatusBadRequest)
		return
	}

	if s.config.InstallsDir == "" {
		http.Error(w, "installs directory not configured", http.StatusServiceUnavailable)
		return
	}

	hostDir := filepath.Join(s.config.InstallsDir, hostname)
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		s.logger.Errorf("install upload: mkdir failed: path=%s error=%v", hostDir, err)
		http.Error(w, "failed to create host directory", http.StatusInternalServerError)
		return
	}

	finalPath := filepath.Join(hostDir, filename)
	partialPath := finalPath + ".partial"

	out, err := os.OpenFile(partialPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		s.logger.Errorf("install upload: create failed: path=%s error=%v", partialPath, err)
		http.Error(w, "failed to open destination", http.StatusInternalServerError)
		return
	}

	limited := io.LimitReader(r.Body, maxInstallLogUploadBytes+1)
	written, copyErr := io.Copy(out, limited)
	closeErr := out.Close()
	if copyErr != nil {
		os.Remove(partialPath)
		s.logger.Errorf("install upload: write failed: path=%s error=%v", partialPath, copyErr)
		http.Error(w, "failed to write body", http.StatusInternalServerError)
		return
	}
	if closeErr != nil {
		os.Remove(partialPath)
		http.Error(w, "failed to close destination", http.StatusInternalServerError)
		return
	}
	if written > maxInstallLogUploadBytes {
		os.Remove(partialPath)
		http.Error(w, "upload exceeds 16 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}

	if err := os.Rename(partialPath, finalPath); err != nil {
		os.Remove(partialPath)
		s.logger.Errorf("install upload: atomic rename failed: from=%s to=%s error=%v", partialPath, finalPath, err)
		http.Error(w, "failed to finalise upload", http.StatusInternalServerError)
		return
	}

	s.logger.Infof("install upload received: hostname=%s filename=%s bytes=%d remote_addr=%s path=%s",
		hostname, filename, written, r.RemoteAddr, finalPath)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusCreated)
	// #nosec G705 -- not an HTML sink. The response is text/plain with
	// nosniff, so no browser parses it as markup, and hostname/filename are
	// not raw request data: they are the capture groups of
	// installMACPathRegexp / installPathRegexp, whose character classes
	// admit no <, >, ", ' or &.
	fmt.Fprintf(w, "stored %d bytes at /installs/%s/%s\n", written, hostname, filename)
}

// handleInstallIndex returns either an HTML directory listing of one host's
// uploads, all hosts, or serves a single uploaded file. Read-only.
func (s *HTTPServer) handleInstallIndex(w http.ResponseWriter, r *http.Request) {
	if s.config.InstallsDir == "" {
		http.Error(w, "installs directory not configured", http.StatusServiceUnavailable)
		return
	}

	relative := strings.TrimPrefix(r.URL.Path, "/installs/")
	if strings.Contains(relative, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	target := filepath.Join(s.config.InstallsDir, relative)

	info, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "stat failed", http.StatusInternalServerError)
		return
	}

	if info.Mode().IsDir() {
		entries, err := os.ReadDir(target)
		if err != nil {
			http.Error(w, "readdir failed", http.StatusInternalServerError)
			return
		}
		data := installIndexData{
			Path:    relative,
			Entries: make([]installIndexEntry, 0, len(entries)),
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				name += "/"
			}
			data.Entries = append(data.Entries, installIndexEntry{Name: name})
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := installIndexTemplate.Execute(w, data); err != nil {
			// The status line is already out, so the response cannot be
			// turned into an error; record it and drop the connection.
			s.logger.Debugf("install index: render failed: %v", err)
		}
		return
	}

	// Serve the file as text/plain so curl/browsers display it inline.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, target)
}

// proxyArgsURLs finds HTTPS URLs in kernel args and converts them to proxy URLs.
func (s *HTTPServer) proxyArgsURLs(args string) string {
	// Find and replace HTTPS URLs in the args string
	result := args
	for {
		idx := strings.Index(result, "https://")
		if idx == -1 {
			break
		}
		// Find the end of the URL (space or end of string)
		endIdx := strings.IndexAny(result[idx:], " \t\n")
		var httpsURL string
		if endIdx == -1 {
			httpsURL = result[idx:]
			result = result[:idx] + s.proxyURL(httpsURL)
		} else {
			httpsURL = result[idx : idx+endIdx]
			result = result[:idx] + s.proxyURL(httpsURL) + result[idx+endIdx:]
		}
	}
	return result
}

// configMACPathRegexp validates /config/mac/{mac}/{key} URLs. MAC is
// normalized lowercase hex with dashes; key is a short lowercase
// identifier. Path traversal is blocked by the explicit ".." guard
// below so the regex doesn't have to defend against it.
var configMACPathRegexp = regexp.MustCompile(`^mac/([0-9a-f\-]{12,17})/([a-z0-9][a-z0-9._\-]{0,64})$`)

// maxConfigValueBytes caps config value writes. Bumped from 4 KiB to
// 256 KiB so the full merged per-node installer.yaml (sdn + network +
// webservices blocks typically runs 10–40 KiB) fits. Plain hostname /
// IP values use a tiny fraction of the budget.
const maxConfigValueBytes int64 = 256 * 1024

// handleConfig serves per-MAC key-value configuration. Shape:
//
//	PUT /config/mac/{mac}/{key}   — orchestrator stages pre-install overrides
//	GET /config/mac/{mac}/{key}   — autoinstall.sh fetches at install time
//
// Values are stored under <InstallsDir>/config/mac/{mac}/{key} so they
// live alongside the install logs and share the same disk bootstrap
// semantics (container bind mount → tmpfs on deployer host). Values are
// plain bytes — no interpretation by the server; the consumer decides
// the format.
func (s *HTTPServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.config.InstallsDir == "" {
		http.Error(w, "installs directory not configured", http.StatusServiceUnavailable)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, "/config/")
	if relative == "" || strings.Contains(relative, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	match := configMACPathRegexp.FindStringSubmatch(relative)
	if match == nil {
		http.Error(w, "path must be mac/{mac}/{key}", http.StatusBadRequest)
		return
	}
	mac, key := match[1], match[2]
	dir := filepath.Join(s.config.InstallsDir, "config", "mac", mac)
	target := filepath.Join(dir, key)

	switch r.Method {
	case http.MethodPut:
		if err := os.MkdirAll(dir, 0o755); err != nil {
			http.Error(w, "mkdir failed", http.StatusInternalServerError)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, maxConfigValueBytes+1))
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if int64(len(data)) > maxConfigValueBytes {
			http.Error(w, "value too large", http.StatusRequestEntityTooLarge)
			return
		}
		tmp := target + ".partial"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmp, target); err != nil {
			os.Remove(tmp)
			http.Error(w, "rename failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("stored\n"))
	case http.MethodGet:
		data, err := os.ReadFile(target)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// #nosec G705 -- not an HTML sink. This echoes a previously stored
		// state value back as text/plain with nosniff; no browser parses it
		// as markup. The value is served to the installer by curl, never
		// rendered in a document.
		_, _ = w.Write(data)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
