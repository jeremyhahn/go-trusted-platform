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

package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// EmbeddedServerBinding manages an in-process platformd instance for
// desktop standalone mode. It initializes the platform App and Daemon,
// then creates an embedded transport client that calls service methods
// directly without any network transport.
type EmbeddedServerBinding struct {
	logger  *slog.Logger
	conn    *ConnectionBinding
	running atomic.Bool
	app     *app.App
	daemon  *daemon.Daemon
}

// NewEmbeddedServerBinding creates a new EmbeddedServerBinding.
func NewEmbeddedServerBinding(logger *slog.Logger, conn *ConnectionBinding) *EmbeddedServerBinding {
	return &EmbeddedServerBinding{
		logger: logger,
		conn:   conn,
	}
}

// IsRunning returns true if the embedded server is running.
func (b *EmbeddedServerBinding) IsRunning() bool {
	return b.running.Load()
}

// Start initializes and starts the embedded platform daemon.
// configPath specifies the path to the platformd config file.
// skipIAMValidation mirrors the --skip-iam-validation flag: pass false in
// production and true only when explicitly requested (e.g. integration tests).
// A prominent WARNING is logged when IAM validation is disabled.
func (b *EmbeddedServerBinding) Start(configPath string, skipIAMValidation bool) error {
	if b.running.Load() {
		return nil
	}

	b.logger.Info("Starting embedded platform daemon", "config", configPath)

	// Desktop standalone startup has no caller-supplied context; the
	// embedded client below already roots itself in Background for the
	// same reason.
	ctx := context.Background()

	// Initialize the platform App
	a := app.NewApp()
	initParams := &app.AppInitParams{
		ConfigFile: configPath,
		Initialize: true,
	}

	if _, err := a.Init(ctx, initParams); err != nil {
		return &EmbeddedServerError{Op: "init", Err: err}
	}
	b.app = a

	// Build daemon config for embedded mode
	config := daemon.DefaultConfig()
	config.App = a

	if skipIAMValidation {
		config.SkipIAMValidation = true
		b.logger.Warn("WARNING: IAM validation is DISABLED for embedded daemon. DO NOT USE IN PRODUCTION.",
			"transports", "embedded")
	}

	// Disable all network protocols for embedded mode
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = false
	config.EnableREST = false
	config.EnableMCP = false

	// Create the daemon (initializes all service implementations)
	d, err := daemon.New(config)
	if err != nil {
		return &EmbeddedServerError{Op: "daemon", Err: err}
	}
	b.daemon = d

	// Build the ServiceRegistry from the daemon's service implementations
	registry := &embedded.ServiceRegistry{
		Daemon: d.Service(),
	}

	// Add optional services if they were initialized
	if svc := d.CAGRPCService(); svc != nil {
		registry.CA = svc
	}
	if svc := d.TPMGRPCService(); svc != nil {
		registry.TPM = svc
	}
	if svc := d.VTPMServiceServer(); svc != nil {
		registry.VTPM = svc
	}
	if svc := d.DeviceGRPCService(); svc != nil {
		registry.Device = svc
	}
	if svc := d.SDNService(); svc != nil {
		registry.SDN = svc
	}
	if svc := d.ComputeGRPCService(); svc != nil {
		registry.Compute = svc
	}
	if svc := d.IDevIDGRPCService(); svc != nil {
		registry.IDevID = svc
	}
	if svc := d.AttestationGRPCService(); svc != nil {
		registry.Attestation = svc
	}

	// Create embedded transport client
	cl, err := platform.NewClient(
		ctx,
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(registry),
	)
	if err != nil {
		return &EmbeddedServerError{Op: "client", Err: err}
	}

	// Inject client into ConnectionBinding
	b.conn.SetClient(&cl)
	b.running.Store(true)

	b.logger.Info("Embedded platform daemon started")
	return nil
}

// Stop shuts down the embedded platform daemon.
func (b *EmbeddedServerBinding) Stop() error {
	if !b.running.Load() {
		return nil
	}

	b.logger.Info("Stopping embedded platform daemon")

	// Disconnect the client first
	if err := b.conn.Disconnect(); err != nil {
		b.logger.Error("Failed to disconnect client", "error", err)
	}

	// Stop the daemon
	if b.daemon != nil {
		if err := b.daemon.Stop(context.Background()); err != nil {
			b.logger.Error("Failed to stop daemon", "error", err)
		}
	}

	b.running.Store(false)
	b.logger.Info("Embedded platform daemon stopped")
	return nil
}

// EmbeddedServerError is returned when the embedded server fails.
type EmbeddedServerError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *EmbeddedServerError) Error() string {
	return "platformctl: embedded server " + e.Op + " failed: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *EmbeddedServerError) Unwrap() error {
	return e.Err
}
