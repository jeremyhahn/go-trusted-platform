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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// The host serves the daemon's services to the embedded transport with every
// network listener off, and every call carries this process's credentials:
// the identity a Unix socket peer has (#691).
func TestNewEmbeddedHost_ServesTheDaemonInProcessOnly(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))
	config.EnableGRPCTCP = true
	config.EnableGRPCUDS = true
	config.EnableQUIC = true
	config.EnableREST = true
	config.EnableMCP = true

	host, err := NewEmbeddedHost(config)
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}
	if config.EnableGRPCTCP || config.EnableGRPCUDS || config.EnableQUIC || config.EnableREST || config.EnableMCP {
		t.Fatalf("a network transport is still enabled: %+v", config)
	}

	services := host.Services()
	if services.Device != nil {
		t.Fatalf("Device = %T, want nil: an unconfigured service must not be a typed nil", services.Device)
	}
	creds, ok := peercred.UnixCredentialsFromContext(services.CallerContext(context.Background()))
	if !ok || creds.UID != uint32(os.Geteuid()) || creds.PID != int32(os.Getpid()) {
		t.Fatalf("caller credentials = %v (found %v), want this process's", creds, ok)
	}

	adapter, err := embedded.New(services)
	if err != nil {
		t.Fatalf("embedded.New: %v", err)
	}
	resp, err := platformv1.NewPlatformDaemonClient(adapter.Connection()).GetVersion(context.Background(), &platformv1.GetVersionRequest{})
	if err != nil {
		t.Fatalf("GetVersion over the embedded transport: %v", err)
	}
	// The version string comes from ldflags, so a test binary's is empty;
	// the answer itself is what shows the daemon served the call.
	if resp == nil {
		t.Fatal("GetVersion returned no response")
	}

	if err := host.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// The ceremony, PIV and FIDO2 services answer on the embedded transport as
// they do over the socket.
func TestNewEmbeddedHost_ServesTheAuthenticatorServices(t *testing.T) {
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}

	services := host.Services()
	if services.Ceremony != platformv1.CeremonyServiceServer(host.daemon.CeremonyService()) {
		t.Errorf("Ceremony = %v, want the daemon's service", services.Ceremony)
	}
	if services.PIV != platformv1.PIVServiceServer(host.daemon.PIVService()) {
		t.Errorf("PIV = %v, want the daemon's service", services.PIV)
	}
	if services.FIDO2 != platformv1.FIDO2ServiceServer(host.daemon.FIDO2Service()) {
		t.Errorf("FIDO2 = %v, want the daemon's service", services.FIDO2)
	}

	if err := host.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// The embedder's wiring is handed the hosted daemon; without a hook there is
// nothing to wire.
func TestEmbeddedHost_WireBackendsReceivesTheDaemon(t *testing.T) {
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}

	if err := host.wireBackends(context.Background(), nil); err != nil {
		t.Fatalf("wireBackends(nil): %v", err)
	}

	var wired *Daemon
	err = host.wireBackends(context.Background(), func(d *Daemon, _ *app.App) error {
		wired = d
		return nil
	})
	if err != nil {
		t.Fatalf("wireBackends: %v", err)
	}
	if wired != host.daemon {
		t.Fatalf("wired daemon = %p, want the host's %p", wired, host.daemon)
	}
}

// errWiringRefused is the failure a test's backend wiring reports.
type errWiringRefused struct{}

func (errWiringRefused) Error() string { return "wiring refused" }

// A failed wiring stops the host and names the step, keeping the cause.
func TestEmbeddedHost_WireBackendsFailureStopsTheHost(t *testing.T) {
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}

	err = host.wireBackends(context.Background(), func(*Daemon, *app.App) error {
		return errWiringRefused{}
	})

	var failed ErrEmbeddedHostFailed
	if !errors.As(err, &failed) || failed.Op != "backends" {
		t.Fatalf("err = %v, want ErrEmbeddedHostFailed{Op: backends}", err)
	}
	if !errors.Is(err, errWiringRefused{}) {
		t.Fatalf("err = %v, want it to keep the wiring's cause", err)
	}
	if host.daemon.IsRunning() {
		t.Fatal("daemon still running after a failed wiring")
	}
}

// AttachNodeCA attaches the node's loaded CA as the daemon's CA service.
func TestAttachNodeCA_AttachesTheNodeCA(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))
	nodeCA := &configurableMockCA{isInitialized: true}
	config.App = &app.App{Logger: logging.DefaultLogger(), CA: nodeCA}

	if err := AttachNodeCA(context.Background(), config, nil); err != nil {
		t.Fatalf("AttachNodeCA: %v", err)
	}
	if config.CAService != nodeCA {
		t.Fatalf("CAService = %v, want the node CA", config.CAService)
	}
}

// A host built from a configured node's config serves the node CA.
func TestNewEmbeddedHost_ServesTheNodeCA(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))
	nodeCA := &configurableMockCA{isInitialized: true, identity: "node-ca"}
	config.CAService = nodeCA

	host, err := NewEmbeddedHost(config)
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}
	svc, ok := host.Services().CA.(*CAGRPCService)
	if !ok || svc.TrustAnchor() != nodeCA {
		t.Fatalf("CA service = %T, want the daemon's CA service over the node CA", host.Services().CA)
	}

	adapter, err := embedded.New(host.Services())
	if err != nil {
		t.Fatalf("embedded.New: %v", err)
	}
	resp, err := platformv1.NewCAServiceClient(adapter.Connection()).GetCAInfo(context.Background(), &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("GetCAInfo over the embedded transport: %v", err)
	}
	if !resp.GetCaInfo().GetIsInitialized() || resp.GetCaInfo().GetCommonName() != "node-ca" {
		t.Fatalf("CA info = %v, want the initialized node CA", resp.GetCaInfo())
	}
}

// A node without a CA still answers CA calls, with ErrCANotInitialized, not
// an unregistered method.
func TestNewEmbeddedHost_WithoutACARefusesSignCSR(t *testing.T) {
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	if err != nil {
		t.Fatalf("NewEmbeddedHost: %v", err)
	}
	services := host.Services()
	// Root passes sign-csr's authorization, so the refusal is the CA's.
	services.CallerContext = func(ctx context.Context) context.Context {
		return peercred.ContextWithUnixCredentials(ctx, peercred.UnixCredentials{UID: 0})
	}

	adapter, err := embedded.New(services)
	if err != nil {
		t.Fatalf("embedded.New: %v", err)
	}
	_, err = platformv1.NewCAServiceClient(adapter.Connection()).SignCSR(context.Background(), &platformv1.SignCSRRequest{CsrPem: "csr"})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition || st.Message() != (ErrCANotInitialized{}).Error() {
		t.Fatalf("SignCSR err = %v, want FailedPrecondition %q", err, ErrCANotInitialized{})
	}
}

func TestAttachNodeCA_RefusesAConfigWithoutAnApp(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))

	err := AttachNodeCA(context.Background(), config, nil)
	if !errors.Is(err, app.ErrCANotConfigured{}) {
		t.Fatalf("err = %v, want app.ErrCANotConfigured", err)
	}
	if config.CAService != nil {
		t.Fatalf("CAService = %T, want nil", config.CAService)
	}
}

func TestNewEmbeddedHost_RefusesAnInvalidConfig(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))
	config.ShutdownTimeout = -1

	host, err := NewEmbeddedHost(config)
	if host != nil {
		t.Fatalf("host = %v, want nil", host)
	}
	var failed ErrEmbeddedHostFailed
	if !errors.As(err, &failed) || failed.Op != "daemon" {
		t.Fatalf("err = %v, want ErrEmbeddedHostFailed{Op: daemon}", err)
	}
}

// A platformd config that cannot be read stops the host before any service
// is built.
func TestStartEmbeddedHost_RefusesAnUnreadableConfigFile(t *testing.T) {
	t.Cleanup(viper.Reset)

	host, err := StartEmbeddedHost(context.Background(), EmbeddedHostOptions{
		ConfigFile: filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if host != nil {
		t.Fatalf("host = %v, want nil", host)
	}
	var failed ErrEmbeddedHostFailed
	if !errors.As(err, &failed) || failed.Op != "init" {
		t.Fatalf("err = %v, want ErrEmbeddedHostFailed{Op: init}", err)
	}
}
