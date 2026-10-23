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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	devicehandler "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const (
	activationSerial = "tp-cp-01"
	activationMAC    = "52:54:00:aa:bb:cc"
	activationIP     = "10.0.0.5"
	activationPort   = "port1"
	admittedVLAN     = 200
)

// newIDevIDApp returns a device App whose TPM holds the simulator IDevID, with
// the platform key store the daemon builds over the same TPM and key backend.
func newIDevIDApp(t *testing.T, idevid *simulatedIDevID) *App {
	t.Helper()
	ks, err := platform.NewPlatformKeyStore(idevid.TPM, idevid.Backend, idevid.Config.PlatformSRK)
	if err != nil {
		// The SRK is never created here: signing with the IDevID needs only
		// the key store's backend.
		require.ErrorIs(t, err, platform.ErrXKMSNotInitialized)
	}
	return &App{
		Logger:     logging.DefaultLogger(),
		TPM:        idevid.TPM,
		TPMConfig:  *idevid.Config,
		PlatformKS: ks,
	}
}

// fakeOVS stands in for the OVS bridge under the policy engine: it accepts
// every flow and port change, so the engine's own state is what the test reads.
type fakeOVS struct{}

func (fakeOVS) InstallFlow(string, int, string, string) error    { return nil }
func (fakeOVS) InstallFlows(string, []zoneflows.FlowRule) error  { return nil }
func (fakeOVS) DeleteFlow(string, string) error                  { return nil }
func (fakeOVS) DeleteFlowsByPort(string, string) error           { return nil }
func (fakeOVS) ListFlows(string) ([]string, error)               { return nil, nil }
func (fakeOVS) SetPortVLAN(context.Context, string, int64) error { return nil }
func (fakeOVS) SetPortTrunk(context.Context, string, []uint16, uint16) error {
	return nil
}
func (fakeOVS) SetPortState(context.Context, string, ovs.PortState) error { return nil }
func (fakeOVS) GetOFPort(context.Context, string) (int32, error)          { return 1, nil }

// profileStore serves the one device profile the enrollment hook looks up by serial.
type profileStore struct {
	devicedao.DeviceProfileDAO
	profile *entities.DeviceProfile
}

func (s profileStore) ForEachPage(_ context.Context, _ datastore.PageQuery, fn datastore.PagerFunc[*entities.DeviceProfile]) error {
	err := fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{s.profile}, Page: 1, PageSize: 100, Total: 1})
	if err == datastore.ErrStopIteration {
		return nil
	}
	return err
}

// activationServer is the control plane's machine-facing device API: the real
// router, mTLS middleware, device handler, SDN enrollment hook and policy
// engine, served over TLS 1.3 the way the webserver serves it.
type activationServer struct {
	srv    *httptest.Server
	issuer *testIssuer
	hook   *policy.SDNEnrollmentHook
	engine *policy.Engine
}

// newActivationServer admits device certificates platformCA issued and serves
// a certificate serverIssuer issued; in production both are the platform CA.
func newActivationServer(t *testing.T, platformCA, serverIssuer *testIssuer) *activationServer {
	t.Helper()
	logger := logging.DefaultLogger()

	engine, err := policy.NewEngine(policy.Config{BridgeName: "br0", FlowController: fakeOVS{}})
	require.NoError(t, err)
	profile := &entities.DeviceProfile{
		ID:         1,
		Name:       "control-plane",
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "tp-cp-"},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork:     {VLAN: 100},
			entities.DefaultPostEnrollmentNetwork: {VLAN: admittedVLAN},
		},
	}
	hook, err := policy.NewSDNEnrollmentHook(policy.SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: engine,
		ProfileDAO:   profileStore{profile: profile},
		MACExtractor: func(ip string) string {
			if ip == activationIP {
				return activationMAC
			}
			return ""
		},
	})
	require.NoError(t, err)

	writer := response.NewResponseWriter(logger, nil)
	handler := devicehandler.NewHandler(logger, writer, hook, v1.NewEnrollmentHookProfileService(hook))
	deviceRouter, err := router.NewDeviceRouter(
		middleware.NewMTLSMiddleware(logger, writer, platformCA.pool()),
		handler,
		struct {
			devicehandler.DeviceCRUDHandler
		}{},
		struct {
			devicehandler.TemplateCRUDHandler
		}{},
		nil,
		nil,
	)
	require.NoError(t, err)
	mainRouter := mux.NewRouter()
	deviceRouter.RegisterMachineFacingRoutes(mainRouter.PathPrefix("/api/v1").Subrouter())

	srv := httptest.NewUnstartedServer(mainRouter)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverIssuer.issueServer(t)},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    platformCA.pool(),
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &activationServer{srv: srv, issuer: serverIssuer, hook: hook, engine: engine}
}

// enroll records the device's enrollment the way the enrollment endpoint does
// once it has issued the certificate: the port moves to enrolled and an
// activation waits for the device.
func (s *activationServer) enroll(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	require.NoError(t, s.engine.SetPortState(activationPort, policy.PortStateProvisioning))
	s.hook.RegisterPort(activationMAC, activationPort)
	require.NoError(t, s.hook.OnEnrollmentComplete(&policy.EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   cert,
		ClientIP:      activationIP,
		IsTCGCSR:      true,
		ProductModel:  "control-plane",
		ProductSerial: activationSerial,
	}))
	s.requirePortState(t, policy.PortStateEnrolled)
}

func (s *activationServer) requirePortState(t *testing.T, want policy.PortState) {
	t.Helper()
	state, err := s.engine.GetPortState(activationPort)
	require.NoError(t, err)
	require.Equal(t, want, state)
}

// serverPool trusts the CA that issued the server's certificate, as a device
// trusts the platform anchor.
func (s *activationServer) serverPool() *x509.CertPool {
	return s.issuer.pool()
}

// TestDeviceActivation_IDevIDOverMTLS proves #149 end to end: a device client
// built by newIDevIDClient presents the simulator IDevID over mTLS, the real
// /api/v1/device/activate chain verifies it and resolves the serial from it,
// and the device's port moves from enrolled to authorized on the admitted VLAN.
func TestDeviceActivation_IDevIDOverMTLS(t *testing.T) {
	idevid := newSimulatedIDevID(t)
	app := newIDevIDApp(t, idevid)
	pub, err := idevid.TPM.IDevID()
	require.NoError(t, err)

	platformCA := newTestIssuer(t)
	cert := platformCA.issueClient(t, activationSerial, pub)

	t.Run("the IDevID activates the device", func(t *testing.T) {
		server := newActivationServer(t, platformCA, platformCA)
		server.enroll(t, cert)

		client, err := app.newIDevIDClient(server.srv.URL, cert, server.serverPool())
		require.NoError(t, err)
		resp, err := client.Activate(context.Background())
		require.NoError(t, err)

		assert.Equal(t, string(policy.ActivationStatusActivated), resp.Status)
		assert.Equal(t, uint16(admittedVLAN), resp.VLAN)
		server.requirePortState(t, policy.PortStateAuthorized)
		vlan, err := server.engine.GetPortVLAN(activationPort)
		require.NoError(t, err)
		assert.Equal(t, uint16(admittedVLAN), vlan)
	})

	t.Run("an IDevID certificate the platform CA did not issue changes nothing", func(t *testing.T) {
		server := newActivationServer(t, platformCA, platformCA)
		server.enroll(t, cert)

		foreign := newTestIssuer(t).issueClient(t, activationSerial, pub)
		client, err := app.newIDevIDClient(server.srv.URL, foreign, server.serverPool())
		require.NoError(t, err)
		_, err = client.Activate(context.Background())
		require.ErrorIs(t, err, provisioning.ErrConnectionFailed)

		server.requirePortState(t, policy.PortStateEnrolled)
	})
}

// TestFetchProfileAndActivate_IDevIDOverMTLS drives the activation an
// installed image performs: platformd's post-enrollment
// App.FetchProfileAndActivate, which fetches the profile and activates with
// the TPM-resident IDevID and verifies the control plane against the platform
// anchor. No key file exists anywhere in the test.
func TestFetchProfileAndActivate_IDevIDOverMTLS(t *testing.T) {
	idevid := newSimulatedIDevID(t)
	pub, err := idevid.TPM.IDevID()
	require.NoError(t, err)

	platformCA := newTestIssuer(t)
	cert := platformCA.issueClient(t, activationSerial, pub)

	// The simulated TPM has no certificate store, so the enrolled IDevID
	// certificate is served the way the store would after enrollment.
	enrolledApp := func(server *activationServer) *App {
		app := newIDevIDApp(t, idevid)
		app.TPM = &anchorTPM{TrustedPlatformModule: idevid.TPM, idevid: cert}
		app.CA = &anchorCA{roots: []*x509.Certificate{platformCA.cert}}
		app.ACMEConfig = &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{
			DirectoryURL: server.srv.URL + "/acme/directory",
		}}
		return app
	}

	t.Run("the device fetches its profile and activates with the IDevID", func(t *testing.T) {
		server := newActivationServer(t, platformCA, platformCA)
		server.enroll(t, cert)

		profile, resp, err := enrolledApp(server).FetchProfileAndActivate(context.Background(), cert)
		require.NoError(t, err)

		assert.Equal(t, uint16(admittedVLAN), profile.AdmittedNetwork.VLAN)
		assert.Equal(t, string(policy.ActivationStatusActivated), resp.Status)
		server.requirePortState(t, policy.PortStateAuthorized)
	})

	t.Run("a control plane outside the platform anchor is refused", func(t *testing.T) {
		server := newActivationServer(t, platformCA, newTestIssuer(t))
		server.enroll(t, cert)

		_, _, err := enrolledApp(server).FetchProfileAndActivate(context.Background(), cert)
		require.ErrorIs(t, err, provisioning.ErrConnectionFailed)

		server.requirePortState(t, policy.PortStateEnrolled)
	})
}

// TestNewIDevIDClient_NoTPM proves a device without a TPM IDevID gets a typed
// error at construction rather than a client that fails at the handshake.
func TestNewIDevIDClient_NoTPM(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	cert := newTestIssuer(t).cert

	client, err := app.newIDevIDClient("https://control-plane.example.com", cert, x509.NewCertPool())
	require.ErrorIs(t, err, provisioning.ErrMissingCertificate)
	assert.Nil(t, client)
}

// TestIDevIDSigner_NilPublicKey proves the signer refuses to build without the
// IDevID's public half: a nil Public() would make crypto/tls present no client
// certificate at all.
func TestIDevIDSigner_NilPublicKey(t *testing.T) {
	app := newIDevIDApp(t, newSimulatedIDevID(t))

	signer, err := app.idevidSigner(nil)
	require.ErrorIs(t, err, ErrIDevIDPublicKeyMissing{})
	assert.Nil(t, signer)
}
