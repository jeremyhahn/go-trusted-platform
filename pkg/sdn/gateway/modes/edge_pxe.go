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

package modes

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// PXEControllerConfig holds configuration for the PXE controller.
type PXEControllerConfig struct {
	// Interface is the network interface for PXE services.
	Interface string

	// HTTPPort is the HTTP server port for boot scripts and files.
	HTTPPort int

	// TFTPPort is the TFTP server port for firmware delivery.
	TFTPPort int

	// DHCPRangeStart is the start of the DHCP IP range.
	DHCPRangeStart string

	// DHCPRangeEnd is the end of the DHCP IP range.
	DHCPRangeEnd string

	// DHCPSubnetMask is the subnet mask for the DHCP pool.
	DHCPSubnetMask string

	// DHCPLeaseSeconds is the DHCP lease time in seconds.
	DHCPLeaseSeconds int

	// KernelPath is the local filesystem path to the kernel image.
	KernelPath string

	// InitrdPath is the local filesystem path to the initrd image.
	InitrdPath string

	// ServerAddr is the gateway's IP address for serving boot files.
	ServerAddr string

	// PlatformdAddr is the control plane address for config delivery.
	PlatformdAddr string

	// BootstrapStrategy is the default bootstrap trust strategy.
	BootstrapStrategy string

	// Logger is the logging.Logger for iPXE server components.
	Logger *logging.Logger
}

// PXEController manages iPXE boot services within the gateway's Edge mode.
type PXEController struct {
	config          *PXEControllerConfig
	ipxeServer      *ipxe.Server
	scriptGenerator *ipxe.ScriptGenerator
	deviceLookup    ipxe.DeviceLookup
	logger          *slog.Logger
	running         atomic.Bool
}

// NewPXEController creates a new PXE controller for edge mode provisioning.
func NewPXEController(config *PXEControllerConfig, logger *slog.Logger) (*PXEController, error) {
	if config == nil {
		return nil, ErrPXEControllerConfigNil
	}
	if logger == nil {
		logger = slog.Default()
	}

	logger = logger.With(slog.String("component", "pxe-controller"))

	scriptGen := ipxe.NewScriptGenerator(config.ServerAddr, logger)

	controller := &PXEController{
		config:          config,
		scriptGenerator: scriptGen,
		logger:          logger,
	}

	// Set the default device lookup that generates boot info from config.
	// In production, this is replaced by a callback that queries platformd
	// via the ProvisioningGateway gRPC service.
	controller.deviceLookup = controller.defaultDeviceLookup

	return controller, nil
}

// Start starts the PXE controller and its underlying iPXE server.
func (c *PXEController) Start(ctx context.Context) error {
	if c.running.Load() {
		return ErrAlreadyRunning
	}

	c.logger.Info("starting PXE controller",
		"interface", c.config.Interface,
		"http_port", c.config.HTTPPort,
		"tftp_port", c.config.TFTPPort,
		"server_addr", c.config.ServerAddr,
	)

	// Determine local files directory from kernel path
	localFilesDir := ""
	if c.config.KernelPath != "" {
		localFilesDir = parentDir(c.config.KernelPath)
	}

	// Build the iPXE server config
	serverConfig := &ipxe.ServerConfig{
		Interface:     c.config.Interface,
		HTTPPort:      c.config.HTTPPort,
		TFTPPort:      c.config.TFTPPort,
		LocalFilesDir: localFilesDir,
		EnableDHCP:    false, // DHCP is handled separately by edge mode
		ExternalURL:   fmt.Sprintf("http://%s:%d", c.config.ServerAddr, c.config.HTTPPort),
		BootEntries: []ipxe.BootEntry{
			{
				Name:        "platform",
				Description: "Trusted Platform Auto-Install",
				Kernel:      fmt.Sprintf("http://%s:%d/files/vmlinuz", c.config.ServerAddr, c.config.HTTPPort),
				Initrd:      fmt.Sprintf("http://%s:%d/files/initramfs", c.config.ServerAddr, c.config.HTTPPort),
			},
		},
	}

	ipxeLogger := c.config.Logger
	if ipxeLogger == nil {
		ipxeLogger = logging.DefaultLogger()
	}

	server, err := ipxe.NewServer(serverConfig, ipxeLogger)
	if err != nil {
		return &ErrStartFailed{Component: "ipxe-server", Cause: err}
	}
	c.ipxeServer = server

	// Configure the HTTP server with device lookup for per-device boot scripts
	c.ipxeServer.HTTPServer().SetDeviceLookup(c.deviceLookup, c.scriptGenerator)

	c.running.Store(true)

	// Start the iPXE server in a goroutine (it blocks until context is done)
	go func() {
		if err := c.ipxeServer.Start(ctx); err != nil {
			c.logger.Error("iPXE server error", "error", err.Error())
			c.running.Store(false)
		}
	}()

	c.logger.Info("PXE controller started")
	return nil
}

// Stop stops the PXE controller.
func (c *PXEController) Stop() error {
	if !c.running.Load() {
		return ErrNotRunning
	}

	c.logger.Info("stopping PXE controller")

	if c.ipxeServer != nil {
		if err := c.ipxeServer.Stop(); err != nil {
			return &ErrStopFailed{Component: "ipxe-server", Cause: err}
		}
	}

	c.running.Store(false)
	c.logger.Info("PXE controller stopped")
	return nil
}

// IsRunning returns whether the PXE controller is currently running.
func (c *PXEController) IsRunning() bool {
	return c.running.Load()
}

// SetDeviceLookup replaces the device lookup callback. This must be called
// before Start to take effect.
func (c *PXEController) SetDeviceLookup(lookup ipxe.DeviceLookup) {
	c.deviceLookup = lookup
}

// defaultDeviceLookup provides a basic device lookup that returns boot info
// using the controller's configuration. In production, this is replaced by a
// callback that queries platformd via the ProvisioningGateway gRPC service.
func (c *PXEController) defaultDeviceLookup(mac string) (*ipxe.DeviceBootInfo, error) {
	c.logger.Info("default device lookup", "mac", mac)

	return &ipxe.DeviceBootInfo{
		MAC:               mac,
		Role:              "worker",
		KernelURL:         fmt.Sprintf("http://%s:%d/files/vmlinuz", c.config.ServerAddr, c.config.HTTPPort),
		InitrdURL:         fmt.Sprintf("http://%s:%d/files/initramfs", c.config.ServerAddr, c.config.HTTPPort),
		ConfigServerURL:   c.config.PlatformdAddr,
		BootstrapStrategy: c.config.BootstrapStrategy,
	}, nil
}

// parentDir returns the parent directory of a file path.
func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
