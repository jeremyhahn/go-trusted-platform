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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/pin/tftp/v3"
)

const (
	// iPXE firmware download URLs
	//
	// Three architectures are served so PXE clients receive a boot
	// image their firmware can actually execute. The DHCP server
	// inspects DHCP option 93 (client system architecture) and
	// hands back the appropriate filename:
	//
	//   arch 0x0000 (legacy BIOS x86)     -> undionly.kpxe
	//   arch 0x0006 (UEFI IA32)           -> ipxe32.efi
	//   arch 0x0007 (UEFI x64) / 0x0009   -> ipxe.efi
	//
	// Serving a UEFI binary to a legacy-BIOS PXE ROM (the historical
	// behavior) causes the client to silently fail the TFTP load and
	// loop the DISCOVER, leaving the operator with no error signal.
	ipxeEFI64Path = "/x86_64-efi/ipxe.efi"
	ipxeEFI32Path = "/i386-efi/ipxe.efi"
	ipxeBIOSPath  = "/undionly.kpxe"
	// ipxeEFIAArch64Path is the arm64 build that drives the firmware's own
	// network stack (SNP): what U-Boot's EFI netboot on a Raspberry Pi or
	// the QEMU virt machine can run.
	ipxeEFIAArch64Path = "/arm64-efi/snponly.efi"

	// FirmwareSNPOnlyAArch64 is the name the arm64 iPXE is served under
	// (arch 0x000b in DefaultBootFilenameByArch).
	FirmwareSNPOnlyAArch64 = "snponly-aarch64.efi"

	// DefaultFirmwareUpstream is the defaults-layer value of
	// ServerConfig.FirmwareUpstream: the iPXE project's release server.
	DefaultFirmwareUpstream = "https://boot.ipxe.org"

	// tftpTimeout is the timeout for TFTP transfers
	tftpTimeout = 5 * time.Second

	// httpTimeout is the timeout for firmware downloads
	httpTimeout = 60 * time.Second

	// cacheDirName is the name of the cache directory
	cacheDirName = "go-trusted-platform"

	// firmwareSubDir is the subdirectory for firmware files
	firmwareSubDir = "firmware"

	// systemCacheDir is the system-wide cache root used when the process
	// has no per-user cache directory (Docker, root, system services).
	systemCacheDir = "/var/cache"
)

// TFTPServer represents a TFTP server for serving iPXE firmware.
type TFTPServer struct {
	config     *ServerConfig
	serverIP   net.IP
	logger     *logging.Logger
	firmware   map[string][]byte
	firmwareMu sync.RWMutex
	server     *tftp.Server
	// downloadTimeout bounds one firmware download; tests shorten it.
	downloadTimeout time.Duration
}

// NewTFTPServer creates a new TFTP server instance.
func NewTFTPServer(cfg *ServerConfig, serverIP net.IP, logger *logging.Logger) *TFTPServer {
	return &TFTPServer{
		config:   cfg,
		serverIP: serverIP,
		logger:   logger,
		firmware: make(map[string][]byte),
	}
}

// Start begins the TFTP server with proper shutdown handling.
func (s *TFTPServer) Start(ctx context.Context, bound chan<- struct{}) error {
	// Load iPXE firmware before starting
	if err := s.loadFirmware(); err != nil {
		return &WrappedError{Msg: "failed to load firmware", Err: err}
	}

	addr := fmt.Sprintf(":%d", s.config.TFTPPort)

	// Create TFTP server with read handler
	s.server = tftp.NewServer(s.readHandler, nil)
	s.server.SetTimeout(tftpTimeout)

	s.logger.Info("TFTP server starting",
		"address", addr,
		"timeout", tftpTimeout,
	)

	// Bind BEFORE serving. ListenAndServe binds inside its own blocking
	// call, so a port conflict surfaced only after the caller had
	// already treated the server as started.
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return &WrappedError{Msg: "TFTP server failed to bind " + addr, Err: err}
	}
	// This function owns the socket: Serve may return without closing a
	// caller-supplied PacketConn, and a cancel landing between the bind
	// and Serve would otherwise leave the TFTP port held after shutdown.
	defer conn.Close()
	signalBound(bound)

	errChan := make(chan error, 1)
	go func() {
		if err := s.server.Serve(conn); err != nil {
			errChan <- &WrappedError{Msg: "TFTP server error", Err: err}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("TFTP server shutting down")
		s.server.Shutdown()
		return nil
	case err := <-errChan:
		return err
	}
}

// readHandler handles TFTP read requests from clients.
func (s *TFTPServer) readHandler(filename string, rf io.ReaderFrom) error {
	s.logger.Debug("TFTP read request received", "filename", filename)

	// Get remote address for logging
	if transfer, ok := rf.(tftp.OutgoingTransfer); ok {
		raddr := transfer.RemoteAddr()
		local := ""
		if info, ok := rf.(tftp.RequestPacketInfo); ok && info.LocalIP() != nil {
			local = info.LocalIP().String()
		}
		s.logger.Debug("TFTP client connected", "remote", raddr.String(), "local", local, "filename", filename)
	}

	// Look up the file in firmware cache
	s.firmwareMu.RLock()
	data, ok := s.firmware[filename]
	s.firmwareMu.RUnlock()

	if !ok {
		if s.config.TFTPDir != "" {
			return s.serveFromDir(filename, rf)
		}
		s.logger.Warn("TFTP file not found", "filename", filename)
		return &SentinelCauseError{Sentinel: ErrFirmwareNotFound, Cause: &MessageError{Msg: filename}}
	}

	// Set transfer size for the client
	if transfer, ok := rf.(tftp.OutgoingTransfer); ok {
		transfer.SetSize(int64(len(data)))
	}

	// Transfer the file
	n, err := rf.ReadFrom(bytes.NewReader(data))
	if err != nil {
		s.logger.Error(&WrappedError{Msg: "TFTP transfer error", Err: err},
			"filename", filename,
		)
		return err
	}

	s.logger.Info("TFTP transfer complete",
		"filename", filename,
		"bytes", n,
	)

	return nil
}

// serveFromDir serves filename from ServerConfig.TFTPDir. The path is
// taken root-relative; one that escapes the tree is refused. A file that
// is not there is reported with os.ErrNotExist, which reaches the client
// as TFTP error 1 (file not found) — the Raspberry Pi bootloader relies on
// that to fall back from its per-device directory to the root.
func (s *TFTPServer) serveFromDir(filename string, rf io.ReaderFrom) error {
	rel := filepath.Clean("/" + filepath.FromSlash(filename))
	full := filepath.Join(s.config.TFTPDir, rel)
	if rel == "/" || !strings.HasPrefix(full, filepath.Clean(s.config.TFTPDir)+string(filepath.Separator)) {
		s.logger.Warn("TFTP request refused", "filename", filename)
		return &TFTPPathError{Filename: filename, Err: os.ErrNotExist}
	}
	f, err := os.Open(full)
	if err != nil {
		s.logger.Debug("TFTP file not in tree", "filename", filename, "path", full)
		return &TFTPPathError{Filename: filename, Err: err}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return &TFTPPathError{Filename: filename, Err: err}
	}
	if info.IsDir() {
		return &TFTPPathError{Filename: filename, Err: os.ErrNotExist}
	}
	if transfer, ok := rf.(tftp.OutgoingTransfer); ok {
		transfer.SetSize(info.Size())
	}
	n, err := rf.ReadFrom(f)
	if err != nil {
		s.logger.Error(&WrappedError{Msg: "TFTP transfer error", Err: err}, "filename", filename)
		return err
	}
	s.logger.Info("TFTP transfer complete", "filename", filename, "path", full, "bytes", n)
	return nil
}

// loadFirmware downloads or loads iPXE firmware from cache.
func (s *TFTPServer) loadFirmware() error {
	cacheDir := s.getCacheDir()

	// Required firmware (64-bit EFI) - server won't start without this
	requiredFirmware := map[string]string{
		"ipxe.efi": s.firmwareURL(ipxeEFI64Path),
	}

	// Optional firmware (32-bit EFI + legacy BIOS) - server still
	// starts if these aren't available, but PXE clients on those
	// architectures won't successfully boot. undionly.kpxe is the
	// 16-bit MBR-style binary required by legacy-BIOS PXE ROMs
	// (Supermicro X10 with BIOS-mode boot, older HPE/Dell systems).
	optionalFirmware := map[string]string{
		"ipxe32.efi":           s.firmwareURL(ipxeEFI32Path),
		"undionly.kpxe":        s.firmwareURL(ipxeBIOSPath),
		FirmwareSNPOnlyAArch64: s.firmwareURL(ipxeEFIAArch64Path),
	}

	// The operator's own builds come first and are never replaced by the
	// cache or a download.
	if err := s.loadFirmwareOverrides(); err != nil {
		return err
	}

	// Load required firmware
	for filename, url := range requiredFirmware {
		if s.hasFirmware(filename) {
			continue
		}
		if err := s.loadFirmwareFile(filename, url, cacheDir); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to load required firmware %s", filename), Err: err}
		}
	}

	// Try to load optional firmware (don't fail if unavailable)
	for filename, url := range optionalFirmware {
		if s.hasFirmware(filename) {
			continue
		}
		if err := s.loadFirmwareFile(filename, url, cacheDir); err != nil {
			s.logger.Warn("Optional firmware unavailable",
				"filename", filename,
				"error", err,
			)
		}
	}

	return nil
}

// loadFirmwareFile loads an individual firmware file from cache or downloads it.
func (s *TFTPServer) loadFirmwareFile(filename, url, cacheDir string) error {
	cachePath := filepath.Join(cacheDir, filename)

	// Try to load from cache first
	data, err := os.ReadFile(cachePath)
	if err == nil {
		s.logger.Info("Loaded firmware from cache",
			"filename", filename,
			"size", len(data),
			"path", cachePath,
		)
		return s.storeFirmware(filename, data)
	}

	if s.config.FirmwareOffline {
		return &ErrFirmwareUnavailable{Filename: filename, Dir: cacheDir}
	}

	// Download from URL
	s.logger.Info("Downloading firmware",
		"filename", filename,
		"url", url,
	)

	data, err = s.downloadFile(url)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to download firmware from %s", url), Err: err}
	}

	// Save to cache
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		s.logger.Warn("Failed to create cache directory", "error", err)
	} else {
		if err := os.WriteFile(cachePath, data, 0644); err != nil {
			s.logger.Warn("Failed to cache firmware", "error", err)
		} else {
			s.logger.Debug("Firmware cached",
				"filename", filename,
				"path", cachePath,
			)
		}
	}

	s.logger.Info("Firmware downloaded and loaded",
		"filename", filename,
		"size", len(data),
	)
	return s.storeFirmware(filename, data)
}

// storeFirmware makes a loaded binary servable, Authenticode-signing EFI
// binaries first when the server has a signer: a client whose firmware
// enforces Secure Boot (U-Boot with the platform's db preseeded, UEFI with
// the keys enrolled) refuses an unsigned iPXE, and the cached upstream
// copy is never modified so the signature can be redone with another key.
func (s *TFTPServer) storeFirmware(filename string, data []byte) error {
	if s.config.FirmwareSigner != nil && strings.HasSuffix(filename, ".efi") {
		var signed bytes.Buffer
		if err := s.config.FirmwareSigner.Sign(bytes.NewReader(data), &signed); err != nil {
			return &FirmwareSignError{Filename: filename, Err: err}
		}
		s.logger.Info("Signed firmware for Secure Boot clients",
			"filename", filename, "unsigned_size", len(data), "signed_size", signed.Len())
		data = signed.Bytes()
	}
	s.firmwareMu.Lock()
	s.firmware[filename] = data
	s.firmwareMu.Unlock()
	return nil
}

// loadFirmwareOverrides loads every ServerConfig.FirmwareOverrides entry
// into the served set. A missing or unreadable file is
// FirmwareOverrideError: the entry was deliberate, so its absence is a
// misconfiguration, not a reason to fall back to the upstream binary.
func (s *TFTPServer) loadFirmwareOverrides() error {
	for filename, path := range s.config.FirmwareOverrides {
		data, err := os.ReadFile(path)
		if err != nil {
			return &FirmwareOverrideError{Filename: filename, Path: path, Err: err}
		}
		s.logger.Info("Loaded firmware override", "filename", filename, "path", path, "size", len(data))
		if err := s.storeFirmware(filename, data); err != nil {
			return err
		}
	}
	return nil
}

// hasFirmware reports whether filename is already in the served set.
func (s *TFTPServer) hasFirmware(filename string) bool {
	s.firmwareMu.RLock()
	defer s.firmwareMu.RUnlock()
	_, ok := s.firmware[filename]
	return ok
}

// downloadFile downloads a file from the specified URL.
func (s *TFTPServer) downloadFile(url string) ([]byte, error) {
	timeout := s.downloadTimeout
	if timeout <= 0 {
		timeout = httpTimeout
	}
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, &WrappedError{Msg: "HTTP GET failed", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &MessageError{Msg: fmt.Sprintf("HTTP error: status %d (%s)", resp.StatusCode, resp.Status)}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read response body", Err: err}
	}

	return data, nil
}

// firmwareURL joins the configured upstream base with a firmware path.
func (s *TFTPServer) firmwareURL(path string) string {
	base := DefaultFirmwareUpstream
	if s.config != nil && s.config.FirmwareUpstream != "" {
		base = s.config.FirmwareUpstream
	}
	return strings.TrimRight(base, "/") + path
}

// getCacheDir returns the directory firmware is loaded from and cached
// into: the configured FirmwareDir when set, else the per-user or system
// cache directory.
func (s *TFTPServer) getCacheDir() string {
	if s.config != nil && s.config.FirmwareDir != "" {
		return s.config.FirmwareDir
	}
	// Try user cache dir first (for non-root users)
	if cacheDir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cacheDir, cacheDirName, firmwareSubDir)
	}

	// Fall back to /var/cache for Docker/system use (root or system service)
	return filepath.Join(systemCacheDir, cacheDirName, firmwareSubDir)
}
