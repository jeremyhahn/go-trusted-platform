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

package daemon

import (
	"context"
	"errors"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// EmbeddedHostOptions configures platformd hosted inside the calling process.
type EmbeddedHostOptions struct {
	// ConfigFile is the platformd configuration file. Empty searches the
	// locations platformd itself searches.
	ConfigFile string

	// SkipIAMValidation disables IAM validation. Testing only.
	SkipIAMValidation bool

	// WireBackends gives the hosted daemon the backends platformd wires
	// (pkg/app/backends.WireEmbeddedHost), which this package cannot
	// import. Nil leaves the ceremony service unconfigured.
	WireBackends func(*Daemon, *app.App) error
}

// EmbeddedHost is platformd hosted inside the calling process: the daemon's
// services, served to the SDK's embedded transport, with no network listener.
// platformctl runs one for the desktop GUI's standalone mode and for a CLI
// context whose transport is embedded.
type EmbeddedHost struct {
	app      *app.App
	daemon   *Daemon
	services *embedded.ServiceRegistry
}

// StartEmbeddedHost initializes the platform from its configuration and
// hosts the daemon's services in this process.
func StartEmbeddedHost(ctx context.Context, opts EmbeddedHostOptions) (*EmbeddedHost, error) {
	// platformd's --config does the same before the App reads its
	// configuration (pkg/daemon/commands/root.go).
	if opts.ConfigFile != "" {
		viper.SetConfigFile(opts.ConfigFile)
	}

	a := app.NewApp()
	initParams := &app.AppInitParams{
		ConfigFile: opts.ConfigFile,
		Initialize: true,
	}
	if _, err := a.Init(ctx, initParams); err != nil {
		return nil, ErrEmbeddedHostFailed{Op: "init", Err: err}
	}

	config := DefaultConfig()
	config.App = a
	config.SkipIAMValidation = opts.SkipIAMValidation
	// A node without a CA still hosts everything else; its CA calls
	// answer ErrCANotInitialized.
	if err := AttachNodeCA(ctx, config, initParams); err != nil {
		a.Logger.Warn("CA will not be available", "error", err)
	}

	host, err := NewEmbeddedHost(config)
	if err != nil {
		return nil, errors.Join(err, a.Close(ctx))
	}
	host.app = a
	if err := host.wireBackends(ctx, opts.WireBackends); err != nil {
		return nil, err
	}
	return host, nil
}

// wireBackends hands the hosted daemon to the embedder's backend wiring. A
// host whose wiring fails is stopped: it would serve a ceremony that
// answers "not configured".
func (h *EmbeddedHost) wireBackends(ctx context.Context, wire func(*Daemon, *app.App) error) error {
	if wire == nil {
		return nil
	}
	if err := wire(h.daemon, h.app); err != nil {
		return ErrEmbeddedHostFailed{Op: "backends", Err: errors.Join(err, h.Stop(ctx))}
	}
	return nil
}

// NewEmbeddedHost builds the daemon's services from config and serves them
// in-process. It turns off every network transport on config first: an
// embedded host is reachable only through its ServiceRegistry.
func NewEmbeddedHost(config *Config) (*EmbeddedHost, error) {
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = false
	config.EnableREST = false
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		return nil, ErrEmbeddedHostFailed{Op: "daemon", Err: err}
	}
	return &EmbeddedHost{daemon: d, services: d.embeddedServices()}, nil
}

// Services returns the registry the SDK's embedded transport dispatches to.
func (h *EmbeddedHost) Services() *embedded.ServiceRegistry {
	return h.services
}

// Stop stops the daemon if it was started and releases the platform's
// resources.
func (h *EmbeddedHost) Stop(ctx context.Context) error {
	var errs []error
	if h.daemon.IsRunning() {
		errs = append(errs, h.daemon.Stop(ctx))
	}
	if h.app != nil {
		errs = append(errs, h.app.Close(ctx))
	}
	if err := errors.Join(errs...); err != nil {
		return ErrEmbeddedHostFailed{Op: "stop", Err: err}
	}
	return nil
}

// embeddedServices builds the ServiceRegistry for the daemon's services.
// Every call is this process's own, so it carries the identity a Unix
// socket peer has: root may do what root may over the socket, and anyone
// else is refused what needs root (sign-csr, #691).
func (d *Daemon) embeddedServices() *embedded.ServiceRegistry {
	registry := &embedded.ServiceRegistry{
		Daemon:        d.Service(),
		CallerContext: peercred.ContextWithProcessCredentials,
	}

	// A node without a CA still registers the CA service, so CA calls
	// answer ErrCANotInitialized rather than an unregistered method.
	registry.CA = NewCAGRPCService(logging.DefaultLogger(), nil, nil)
	if svc := d.CAGRPCService(); svc != nil {
		registry.CA = svc
	}

	// DNS is registered the same way: the servicer gRPC and Unix serve,
	// over the same backend, or one that answers not-configured.
	registry.DNS = NewDNSServiceServer(nil, logging.DefaultLogger().Slog())
	if svc := d.DNSGRPCServiceServer(); svc != nil {
		registry.DNS = svc
	}

	// New always builds Cache, Scheduler, Messaging and ObjectStorage: a node
	// whose SDK does not serve them answers Unavailable, as on every other
	// transport.
	if d.appServices.cache != nil {
		registry.Cache = d.appServices.cache
	}
	if d.appServices.scheduler != nil {
		registry.Scheduler = d.appServices.scheduler
	}
	if d.appServices.messaging != nil {
		registry.Messaging = d.appServices.messaging
	}
	if d.appServices.objectStorage != nil {
		registry.ObjectStorage = d.appServices.objectStorage
	}

	// Any other unconfigured service stays a nil interface, never a typed nil.
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
	if svc := d.KMSGRPCService(); svc != nil {
		registry.KMS = svc
	}
	if svc := d.CeremonyService(); svc != nil {
		registry.Ceremony = svc
	}
	if svc := d.PIVService(); svc != nil {
		registry.PIV = svc
	}
	if svc := d.FIDO2Service(); svc != nil {
		registry.FIDO2 = svc
	}
	if svc := d.BMCService(); svc != nil {
		registry.BMC = svc
	}
	if svc := d.NTPGRPCServiceServer(); svc != nil {
		registry.NTP = svc
	}
	if svc := d.LUKSService(); svc != nil {
		registry.LUKS = svc
	}
	if svc := d.BarrierGRPCService(); svc != nil {
		registry.Barrier = svc
	}
	if svc := d.SwitchService(); svc != nil {
		registry.Switch = svc
	}
	return registry
}
