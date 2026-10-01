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

package container

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// shutdownTimeout is the maximum time to wait for graceful HTTP shutdown.
	shutdownTimeout = 5 * time.Second
)

// Server wraps pkg/ipxe.Server with manifest-based boot script generation.
type Server struct {
	ipxeServer *ipxe.Server
	manifest   *Manifest
	config     *ServerConfig
	logger     *slog.Logger
	httpServer *http.Server
	running    atomic.Bool
	mu         sync.Mutex

	// sets are the media sets served, by name; defaults the set each
	// architecture's unknown machines boot.
	sets      map[string]MediaSet
	defaults  map[string]MediaSet
	scriptGen *ipxe.ScriptGenerator
}

// alpineRepoBranch derives the Alpine repository branch path component
// (e.g. "v3.22") from a full version like "3.22.2". It mirrors the URL
// layout Alpine mirrors use (<base>/v3.22/main). An empty version yields an
// empty branch; callers default AlpineVersion before reaching here, so in
// practice the branch is always populated.
func alpineRepoBranch(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return "v" + parts[0] + "." + parts[1]
	}
	if version == "" {
		return ""
	}
	return "v" + version
}

// NewServer creates a new bootstrap container server.
func NewServer(config *ServerConfig, logger *slog.Logger) (*Server, error) {
	if config == nil {
		return nil, ErrInvalidServerConfig{Field: "config", Reason: "must not be nil"}
	}
	if logger == nil {
		return nil, ErrInvalidServerConfig{Field: "logger", Reason: "must not be nil"}
	}

	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	manifest, err := LoadManifest(config.ManifestPath)
	if err != nil {
		return nil, err
	}

	sets, err := mediaSets(config)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]MediaSet, len(sets))
	defaults := make(map[string]MediaSet)
	var entries []ipxe.BootEntry
	for _, set := range sets {
		byName[set.Name] = set
		if set.Default {
			defaults[set.Architecture] = set
			entries = append(entries, set.bootEntry(config))
		}
	}
	if err := manifest.checkMediaSets(byName, defaults); err != nil {
		return nil, err
	}

	// Build the underlying ipxe.ServerConfig for the iPXE server.
	ipxeConfig := &ipxe.ServerConfig{
		Interface:        config.Interface,
		HTTPPort:         config.HTTPPort,
		TFTPPort:         config.TFTPPort,
		FirmwareDir:      config.FirmwareDir,
		FirmwareUpstream: config.FirmwareUpstream,
		FirmwareOffline:  config.FirmwareOffline,
		LocalFilesDir:    config.ConfigDir,
		// Install-log uploads land in /data/installs/{hostname}/ inside the
		// container — same volume mount as the SMB share, so /data persists
		// across container restarts and is browseable both via SMB and via
		// HTTP at /installs/.
		InstallsDir: filepath.Join(config.DataDir, "installs"),
		// /data is the bind-mounted host directory inside the container.
		// Exposing it under HTTP /data/ serves the media sets the boot
		// scripts' kernel / initrd / modloop= URLs name (/data/media/<set>/…).
		DataDir:           config.DataDir,
		EnableDHCP:        true,
		DHCPRangeStart:    config.DHCPConfig.RangeStart,
		DHCPRangeEnd:      config.DHCPConfig.RangeEnd,
		DHCPSubnetMask:    config.DHCPConfig.SubnetMask,
		DHCPGateway:       config.DHCPConfig.Gateway,
		DHCPLeaseTime:     config.DHCPConfig.LeaseTime,
		DHCPServerIP:      config.DHCPConfig.ServerIP,
		DHCPPort:          config.DHCPConfig.Port,
		DHCPRespondToAll:  true, // Bootstrap mode: respond to all DHCP clients, not just PXE
		BootFilename:      "ipxe.efi",
		BootEntries:       entries,
		TFTPDir:           config.TFTPDir,
		FirmwareOverrides: config.FirmwareOverrides,
		DHCPProxyOnly:     config.DHCPProxyOnly,
	}
	if len(config.DHCPConfig.DNS) > 0 {
		ipxeConfig.DHCPDNS = config.DHCPConfig.DNS[0]
	}

	loggingLogger := logging.DefaultLogger()
	ipxeServer, err := ipxe.NewServer(ipxeConfig, loggingLogger)
	if err != nil {
		return nil, ErrServerStartFailed{Cause: err}
	}

	server := &Server{
		ipxeServer: ipxeServer,
		manifest:   manifest,
		config:     config,
		logger:     logger,
		sets:       byName,
		defaults:   defaults,
		scriptGen:  ipxe.NewScriptGenerator(serverBaseURL(config), logger),
	}
	// /boot.ipxe chains the per-device route first: a node in the
	// manifest boots its media set, with its role and hostname.
	ipxeServer.HTTPServer().SetDeviceLookup(server.deviceBootInfo, server.scriptGen)
	return server, nil
}

// Start starts the bootstrap server, including DHCP, TFTP, HTTP, and
// deviceScriptAddr returns the listen address of the per-device boot
// script server.
//
// Split out of Start so the address can be asserted without binding a
// socket: the whole point of making the port configurable is that the
// bind is what fails on a busy deployer, so a test that has to bind in
// order to check the address cannot cover the case that matters.
//
// DeviceScriptPort is honoured verbatim; a zero value derives
// HTTPPort+DeviceScriptPortOffset so a Server built without
// ApplyDefaults still lands where it always did.
func (s *Server) deviceScriptAddr() string {
	port := s.config.DeviceScriptPort
	if port == 0 {
		port = s.config.HTTPPort + DeviceScriptPortOffset
	}
	return net.JoinHostPort(s.config.DHCPConfig.ServerIP, strconv.Itoa(port))
}

// the per-device boot script endpoint.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return ErrServerStartFailed{Cause: &MessageError{Msg: "server is already running"}}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/boot/device/", s.HandleDeviceBootScript)

	addr := s.deviceScriptAddr()
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	s.running.Store(true)
	s.mu.Unlock()

	errCh := make(chan error, 2)

	// An internal context, cancelled on every return path. Without it
	// the device-script goroutine parks on Ready() — which deliberately
	// never closes when a listener fails — and outlives a Start that
	// returned an error, holding the goroutine until whoever owns the
	// caller's context happens to cancel it.
	runCtx, cancelRun := context.WithCancel(ctx)
	var running sync.WaitGroup
	defer func() {
		cancelRun()
		running.Wait()
	}()

	running.Add(1)
	go func() {
		defer running.Done()
		if err := s.ipxeServer.Start(runCtx); err != nil && runCtx.Err() == nil {
			errCh <- ErrServerStartFailed{Cause: err}
		}
	}()

	running.Add(1)
	go func() {
		defer running.Done()
		// Bind LAST, once the iPXE server reports every one of its
		// listeners up. That ordering is what makes this port a
		// complete readiness signal: the deploy gate probes it, and if
		// it answers, HTTP, TFTP and DHCP have all bound too. Probing
		// an HTTP port that comes up first would pass while a TFTP or
		// DHCP bind failure was still in flight, and the node would
		// then PXE-boot into nothing.
		select {
		case <-s.ipxeServer.Ready():
		case <-runCtx.Done():
			return
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- ErrServerStartFailed{Cause: err}
			return
		}
		s.logger.Info("starting bootstrap device script server", slog.String("addr", addr))
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- ErrServerStartFailed{Cause: err}
		}
	}()

	select {
	case err := <-errCh:
		s.Stop()
		return err
	case <-ctx.Done():
		return s.Stop()
	}
}

// Stop gracefully stops the bootstrap server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running.Load() {
		return nil
	}
	s.running.Store(false)

	s.logger.Info("stopping bootstrap server")

	var firstErr error

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if err := s.ipxeServer.Stop(); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// deviceBootInfo is the per-device assignment for a MAC: the manifest
// entry's media set (or its architecture's default) with the node's role
// and hostname. A MAC not in the manifest is ipxe.ErrDeviceNotFound, so
// the client falls through to its architecture's default entry.
func (s *Server) deviceBootInfo(mac string) (*ipxe.DeviceBootInfo, error) {
	entry, found := s.manifest.LookupMAC(mac)
	if !found {
		return nil, ErrMACNotInManifest{MAC: mac}
	}
	set, err := s.setFor(entry)
	if err != nil {
		return nil, err
	}
	base := serverBaseURL(s.config)
	return &ipxe.DeviceBootInfo{
		MAC:             mac,
		Role:            entry.Role,
		Hostname:        entry.Hostname,
		Architecture:    set.Architecture,
		KernelURL:       set.url(base, set.Kernel),
		InitrdURL:       set.url(base, set.Initrd),
		ExtraKernelArgs: []string{set.bootArgs(s.config)},
	}, nil
}

// setFor resolves the media set a manifest entry boots.
func (s *Server) setFor(entry *ManifestEntry) (MediaSet, error) {
	if entry.MediaSet != "" {
		set, ok := s.sets[entry.MediaSet]
		if !ok {
			return MediaSet{}, ErrUnknownMediaSet{MAC: entry.MAC, MediaSet: entry.MediaSet}
		}
		return set, nil
	}
	arch := entry.Architecture
	if arch == "" {
		arch = ipxe.ArchitectureX86_64
	}
	set, ok := s.defaults[arch]
	if !ok {
		return MediaSet{}, ErrUnknownMediaSet{MAC: entry.MAC, Architecture: arch}
	}
	return set, nil
}

// HandleDeviceBootScript serves /boot/device/{mac}.ipxe on the device-script
// listener, which the deploy gate probes as its readiness signal. A node
// in the manifest gets exactly the script the iPXE server's own route
// renders; any other MAC gets a script that chains /boot.ipxe, where the
// client's architecture picks its default — never a kernel chosen without
// knowing the architecture.
func (s *Server) HandleDeviceBootScript(w http.ResponseWriter, r *http.Request) {
	mac := extractMACFromPath(r.URL.Path)
	if mac == "" {
		http.Error(w, "missing or malformed MAC address in path", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	info, err := s.deviceBootInfo(mac)
	var script string
	switch {
	case errors.Is(err, ipxe.ErrDeviceNotFound):
		s.logger.Info("serving the default chain for an unknown device", slog.String("mac", mac))
		script = "#!ipxe\nchain " + serverBaseURL(s.config) + "/boot.ipxe\n"
	case err != nil:
		s.logger.Error("device boot script", slog.String("mac", mac), slog.String("error", err.Error()))
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	default:
		s.logger.Info("serving device boot script", slog.String("mac", mac), slog.String("hostname", info.Hostname))
		script = s.scriptGen.GenerateScript(info)
	}
	// #nosec G705 -- not an HTML sink. The body is an iPXE script served as
	// text/plain with nosniff, so no browser renders it as a document. The
	// only request-derived input is the MAC, which extractMACFromPath accepts
	// solely as a parsed 48-bit address in canonical form; the script itself
	// is rendered from the manifest entry that MAC selects.
	if _, err := w.Write([]byte(script)); err != nil {
		s.logger.Warn("writing device boot script", slog.String("error", err.Error()))
	}
}

// extractMACFromPath extracts the MAC address from a URL path like
// /boot/device/aa:bb:cc:dd:ee:ff.ipxe or /boot/device/aa-bb-cc-dd-ee-ff.ipxe
// and returns it in canonical lower-case colon form. Anything that is not a
// 48-bit MAC returns "", so no request-supplied text reaches a lookup, a log
// line or the served script.
func extractMACFromPath(path string) string {
	path = strings.TrimSuffix(strings.TrimPrefix(path, "/boot/device/"), ".ipxe")
	hw, err := net.ParseMAC(path)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}
