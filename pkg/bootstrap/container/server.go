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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// shutdownTimeout is the maximum time to wait for graceful HTTP shutdown.
	shutdownTimeout = 5 * time.Second
)

// deviceBootScriptTmpl is the iPXE script template for a known device.
var deviceBootScriptTmpl = template.Must(template.New("device").Parse(`#!ipxe
kernel http://{{.ServerIP}}:{{.HTTPPort}}/files/vmlinuz alpine_start=autoinstall platform_role={{.Role}} platform_hostname={{.Hostname}}
initrd http://{{.ServerIP}}:{{.HTTPPort}}/files/initramfs
boot
`))

// defaultBootScriptTmpl is the fallback iPXE script for unknown devices.
var defaultBootScriptTmpl = template.Must(template.New("default").Parse(`#!ipxe
echo Unknown device - entering boot menu
kernel http://{{.ServerIP}}:{{.HTTPPort}}/files/vmlinuz alpine_start=autoinstall
initrd http://{{.ServerIP}}:{{.HTTPPort}}/files/initramfs
boot
`))

// deviceScriptData holds template data for per-device iPXE scripts.
type deviceScriptData struct {
	ServerIP string
	HTTPPort int
	Role     string
	Hostname string
}

// defaultScriptData holds template data for the default iPXE script.
type defaultScriptData struct {
	ServerIP string
	HTTPPort int
}

// Server wraps pkg/ipxe.Server with manifest-based boot script generation.
type Server struct {
	ipxeServer *ipxe.Server
	manifest   *Manifest
	config     *ServerConfig
	logger     *slog.Logger
	httpServer *http.Server
	running    atomic.Bool
	mu         sync.Mutex
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

	// Build the underlying ipxe.ServerConfig for the iPXE server.
	ipxeConfig := &ipxe.ServerConfig{
		Interface:      config.Interface,
		HTTPPort:       config.HTTPPort,
		TFTPPort:       config.TFTPPort,
		LocalFilesDir:  config.ConfigDir,
		// Install-log uploads land in /data/installs/{hostname}/ inside the
		// container — same volume mount as the SMB share, so /data persists
		// across container restarts and is browseable both via SMB and via
		// HTTP at /installs/.
		InstallsDir: "/data/installs",
		// /data is the bind-mounted host directory inside the container.
		// Exposing it under HTTP /data/ lets the generated bootstrap.ipxe
		// script's `kernel /data/vmlinuz` / `initrd /data/initramfs`
		// directives resolve to real downloads rather than 404s.
		DataDir: "/data",
		EnableDHCP:     true,
		DHCPRangeStart: config.DHCPConfig.RangeStart,
		DHCPRangeEnd:   config.DHCPConfig.RangeEnd,
		DHCPSubnetMask: config.DHCPConfig.SubnetMask,
		DHCPGateway:    config.DHCPConfig.Gateway,
		DHCPLeaseTime:  config.DHCPConfig.LeaseTime,
		DHCPServerIP:      config.DHCPConfig.ServerIP,
		DHCPRespondToAll: true, // Bootstrap mode: respond to all DHCP clients, not just PXE
		BootFilename:      "ipxe.efi",
		BootEntries: []ipxe.BootEntry{
			{
				Name:        "bootstrap",
				Description: "Bootstrap installer",
				Kernel:      config.KernelPath,
				Initrd:      config.InitrdPath,
				// Kernel cmdline mirrors the grub.cfg that
				// platformctl iso create generates for the same
				// vmlinuz/initramfs pair. Without these args:
				//   - alpine_start=autoinstall: autoinstall.sh
				//     never runs (initramfs init falls through to
				//     a shell), so the install never starts.
				//   - console=ttyS0/ttyS1: kernel doesn't print
				//     to serial, leaving SOL captures silent and
				//     making boot failures invisible to the
				//     operator.
				//   - modules=loop,squashfs,...: required modules
				//     for mounting the Alpine modloop / live
				//     squashfs are not loaded.
				//   - platform_debug=1 + platform_debug_sink:
				//     turns on the kernel-debug log forwarder so
				//     boot diagnostics PUT to /installs/.../
				//     install.log on this same pxeboot host.
				Args: "modules=loop,squashfs,sd-mod,usb-storage " +
					"earlyprintk=efi,keep earlycon=uart8250,io,0x3f8,115200n8 " +
					"console=tty0 console=ttyS1,115200n8 console=ttyS0,115200n8 " +
					"loglevel=7 console=tty1 " +
					"alpine_start=autoinstall " +
					// ip=dhcp — required so the Alpine initramfs
					// init script (nlplug-findfs / mkinitfs) brings
					// up the boot NIC and obtains a DHCP lease
					// BEFORE attempting to fetch modloop= over HTTP.
					// Without this the network isn't configured at
					// modloop-fetch time, the fetch fails, and the
					// kernel boots with only its built-in modules.
					"ip=dhcp " +
					// modloop URL — Alpine's initramfs init looks
					// for the kernel-modules squashfs first on
					// /media/cdrom/boot/modloop-lts (CD boot path)
					// and, when that's absent, fetches a URL passed
					// via the modloop= kernel arg. PXE-booted nodes
					// have no CD; without this arg the kernel boots
					// with the built-in modules only — no extra
					// NIC drivers, no dm-crypt, no LUKS, no LVM —
					// and autoinstall silently dies before it can
					// upload a checkpoint.
					"modloop=http://" + config.DHCPConfig.ServerIP + ":" + fmt.Sprintf("%d", config.HTTPPort) + "/data/modloop-lts " +
					"platform_debug=1 platform_debug_sink=" + config.DHCPConfig.ServerIP + ":" + fmt.Sprintf("%d", config.HTTPPort),
			},
		},
	}
	if len(config.DHCPConfig.DNS) > 0 {
		ipxeConfig.DHCPDNS = config.DHCPConfig.DNS[0]
	}

	loggingLogger := logging.DefaultLogger()
	ipxeServer, err := ipxe.NewServer(ipxeConfig, loggingLogger)
	if err != nil {
		return nil, ErrServerStartFailed{Cause: err}
	}

	return &Server{
		ipxeServer: ipxeServer,
		manifest:   manifest,
		config:     config,
		logger:     logger,
	}, nil
}

// Start starts the bootstrap server, including DHCP, TFTP, HTTP, and
// the per-device boot script endpoint.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return ErrServerStartFailed{Cause: fmt.Errorf("server is already running")}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/boot/device/", s.HandleDeviceBootScript)

	addr := net.JoinHostPort(s.config.DHCPConfig.ServerIP, fmt.Sprintf("%d", s.config.HTTPPort+1))
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	s.running.Store(true)
	s.mu.Unlock()

	errCh := make(chan error, 2)

	go func() {
		if err := s.ipxeServer.Start(ctx); err != nil && ctx.Err() == nil {
			errCh <- ErrServerStartFailed{Cause: err}
		}
	}()

	go func() {
		s.logger.Info("starting bootstrap device script server", slog.String("addr", addr))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

// HandleDeviceBootScript generates a per-device iPXE script from the manifest.
// It is called by the HTTP server for /boot/device/{mac}.ipxe requests.
func (s *Server) HandleDeviceBootScript(w http.ResponseWriter, r *http.Request) {
	mac := extractMACFromPath(r.URL.Path)
	if mac == "" {
		http.Error(w, "missing MAC address in path", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	entry, found := s.manifest.LookupMAC(mac)
	if found {
		s.logger.Info("serving device boot script",
			slog.String("mac", mac),
			slog.String("role", entry.Role),
			slog.String("hostname", entry.Hostname))

		data := deviceScriptData{
			ServerIP: s.config.DHCPConfig.ServerIP,
			HTTPPort: s.config.HTTPPort,
			Role:     entry.Role,
			Hostname: entry.Hostname,
		}
		if err := deviceBootScriptTmpl.Execute(w, data); err != nil {
			s.logger.Error("failed to execute device boot script template",
				slog.String("error", err.Error()))
		}
		return
	}

	s.logger.Info("serving default boot script for unknown device",
		slog.String("mac", mac))

	data := defaultScriptData{
		ServerIP: s.config.DHCPConfig.ServerIP,
		HTTPPort: s.config.HTTPPort,
	}
	if err := defaultBootScriptTmpl.Execute(w, data); err != nil {
		s.logger.Error("failed to execute default boot script template",
			slog.String("error", err.Error()))
	}
}

// extractMACFromPath extracts the MAC address from a URL path like
// /boot/device/aa:bb:cc:dd:ee:ff.ipxe or /boot/device/aa-bb-cc-dd-ee-ff.ipxe.
func extractMACFromPath(path string) string {
	// Strip prefix /boot/device/
	path = strings.TrimPrefix(path, "/boot/device/")
	// Strip suffix .ipxe
	path = strings.TrimSuffix(path, ".ipxe")
	// Normalize dashes to colons
	path = strings.ReplaceAll(path, "-", ":")
	if path == "" {
		return ""
	}
	return path
}
