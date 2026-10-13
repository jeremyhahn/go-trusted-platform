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

// pxeboot is a minimal container entrypoint that runs the PXE bootstrap
// server. It parses CLI flags, builds a container.ServerConfig, and
// delegates to container.Server for DHCP, TFTP, and HTTP boot services.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

func main() {
	manifest := flag.String("manifest", "", "path to manifest.yaml (required)")
	configDir := flag.String("config-dir", "/data/configs", "directory with per-device configs")
	iface := flag.String("interface", "eth0", "network interface to bind")
	// DHCP does not bind it: it must receive broadcasts, so it keeps the
	// unspecified address on --interface (#93).
	bindHost := flag.String("bind-host", ipxe.DefaultBindHost, "address the HTTP and TFTP servers bind (default: every interface)")
	httpPort := flag.Int("http-port", 8080, "HTTP server port")
	// Zero derives http-port+1, which is where this listener lived when
	// the offset was hardcoded. It is settable because the deployer is
	// routinely a shared jumpbox where something else already owns 8081.
	deviceScriptPort := flag.Int("device-script-port", 0, "per-device boot script server port (default: http-port+1)")
	tftpPort := flag.Int("tftp-port", 69, "TFTP server port")
	dhcpServerIP := flag.String("dhcp-server-ip", "", "DHCP server IP address (required)")
	dhcpRangeStart := flag.String("dhcp-range-start", "", "DHCP range start IP (required)")
	dhcpRangeEnd := flag.String("dhcp-range-end", "", "DHCP range end IP (required)")
	dhcpGateway := flag.String("dhcp-gateway", "", "DHCP gateway to advertise")
	dhcpDNS := flag.String("dhcp-dns", "", "comma-separated DNS servers to advertise")
	// apk-mirror / alpine-version feed the PXE kernel cmdline: PXE nodes have
	// no /media/cdrom, so the Alpine init needs alpine_repo=<mirror>/<branch>
	// to build the live root and the autoinstall needs platform_apk_mirror to
	// resolve packages. Empty values fall through to ServerConfig defaults
	// (public Alpine mirror), keeping internet-connected installs working.
	apkMirror := flag.String("apk-mirror", "", "install-time APK mirror base URL (default: public Alpine mirror)")
	alpineVersion := flag.String("alpine-version", "", "Alpine version of the staged kernel/initramfs (default: "+container.DefaultAlpineVersion+")")
	// Media sets and the Raspberry Pi netboot stage.
	dataDir := flag.String("data-dir", container.DefaultDataDir, "directory served over HTTP at /data/ (the media dir must be inside it)")
	mediaDir := flag.String("media-dir", container.DefaultDataDir+"/"+container.NetbootMediaSetsDir, "directory of the media sets served, one per subdirectory with a media-set.yaml (the netboot media build's media/, under --data-dir)")
	tftpDir := flag.String("tftp-dir", "", "Raspberry Pi boot tree served over TFTP (start4.elf, config.txt, kernel8.img, ...)")
	overrides := firmwareOverrides{}
	flag.Var(overrides, "firmware-override", "serve a prebuilt firmware file in place of the upstream download, as name=path (repeatable), e.g. snponly-aarch64.efi=/data/firmware/snponly-aarch64.efi")
	proxyDHCP := flag.Bool("dhcp-proxy", false, "answer PXE clients with boot options and no lease (the segment has its own DHCP server)")

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	version := app.GetVersion()
	logger.Info("pxeboot starting",
		slog.String("name", version.Name),
		slog.String("version", version.Version),
		slog.String("git_hash", version.GitHash),
		slog.String("build_date", version.BuildDate))

	if err := validateRequiredFlags(*manifest, *mediaDir, *dhcpServerIP, *dhcpRangeStart, *dhcpRangeEnd); err != nil {
		logger.Error("missing required flag", slog.String("error", err.Error()))
		flag.Usage()
		os.Exit(1)
	}

	var dnsServers []string
	if *dhcpDNS != "" {
		dnsServers = strings.Split(*dhcpDNS, ",")
	}

	config := &container.ServerConfig{
		Interface:         *iface,
		BindHost:          *bindHost,
		HTTPPort:          *httpPort,
		DeviceScriptPort:  *deviceScriptPort,
		TFTPPort:          *tftpPort,
		ManifestPath:      *manifest,
		ConfigDir:         *configDir,
		AlpineVersion:     *alpineVersion,
		APKMirror:         *apkMirror,
		DataDir:           *dataDir,
		MediaDir:          *mediaDir,
		TFTPDir:           *tftpDir,
		FirmwareOverrides: overrides,
		DHCPProxyOnly:     *proxyDHCP,
		DHCPConfig: container.DHCPConfig{
			ServerIP:   *dhcpServerIP,
			RangeStart: *dhcpRangeStart,
			RangeEnd:   *dhcpRangeEnd,
			Gateway:    *dhcpGateway,
			DNS:        dnsServers,
		},
	}

	server, err := container.NewServer(config, logger)
	if err != nil {
		logger.Error("failed to create server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
	}()

	logger.Info("starting PXE bootstrap server",
		slog.String("interface", *iface),
		slog.String("bind_host", *bindHost),
		slog.Int("http_port", *httpPort),
		slog.Int("tftp_port", *tftpPort),
		slog.String("dhcp_server_ip", *dhcpServerIP),
		slog.String("dhcp_range", *dhcpRangeStart+"-"+*dhcpRangeEnd))

	if err := server.Start(ctx); err != nil {
		logger.Error("server exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("pxeboot shutdown complete")
}

// validateRequiredFlags checks that all required string flags are non-empty.
func validateRequiredFlags(manifest, mediaDir, serverIP, rangeStart, rangeEnd string) error {
	required := map[string]string{
		"--manifest":         manifest,
		"--media-dir":        mediaDir,
		"--dhcp-server-ip":   serverIP,
		"--dhcp-range-start": rangeStart,
		"--dhcp-range-end":   rangeEnd,
	}
	var missing []string
	for name, value := range required {
		if value == "" {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return &MessageError{Msg: fmt.Sprintf("required flags not set: %s", strings.Join(missing, ", "))}
	}
	return nil
}

// firmwareOverrides is the repeatable --firmware-override name=path flag.
type firmwareOverrides map[string]string

func (f firmwareOverrides) String() string {
	names := make([]string, 0, len(f))
	for name := range f {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+f[name])
	}
	return strings.Join(parts, ",")
}

func (f firmwareOverrides) Set(value string) error {
	name, path, ok := strings.Cut(value, "=")
	if !ok || name == "" || path == "" {
		return &MessageError{Msg: "--firmware-override wants name=path, got " + value}
	}
	if _, dup := f[name]; dup {
		return &MessageError{Msg: "--firmware-override " + name + " given twice"}
	}
	f[name] = path
	return nil
}
