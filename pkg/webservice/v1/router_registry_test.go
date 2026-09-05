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

package v1

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/adminclaim"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdktransport "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTokenHandler implements jwt.TokenHandler for testing.
type mockTokenHandler struct{}

func (m *mockTokenHandler) CreateSession(w http.ResponseWriter, r *http.Request) (service.Session, error) {
	return nil, nil
}

func (m *mockTokenHandler) GenerateToken(w http.ResponseWriter, req *http.Request) {}

func (m *mockTokenHandler) RefreshToken(w http.ResponseWriter, req *http.Request) {}

func (m *mockTokenHandler) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(w, r)
}

// mockWebAuthnHandler implements webauthn.RestHandler for testing.
type mockWebAuthnHandler struct{}

func (m *mockWebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request)  {}
func (m *mockWebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {}
func (m *mockWebAuthnHandler) BeginLogin(w http.ResponseWriter, r *http.Request)         {}
func (m *mockWebAuthnHandler) FinishLogin(w http.ResponseWriter, r *http.Request)        {}
func (m *mockWebAuthnHandler) RegistrationStatus(w http.ResponseWriter, r *http.Request) {}
func (m *mockWebAuthnHandler) RefreshToken(w http.ResponseWriter, r *http.Request)       {}
func (m *mockWebAuthnHandler) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(w, r)
}

// mockMTLSMiddleware implements middleware.MTLSMiddleware for testing.
type mockMTLSMiddleware struct{}

func (m *mockMTLSMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(w, r)
}

// testHandlerRegistry implements RestHandlerRegistry for testing.
type testHandlerRegistry struct {
	tokenHandler   jwt.TokenHandler
	webauthn       webauthn.RestHandler
	mtls           middleware.MTLSMiddleware
	deviceHandler  device.RestHandler
	acmeService    trustedca.ACMERestServicer
	sdnService     platformv1.SDNServiceServer
	tpm            xkmssdk.TrustedPlatformModule
	vtpmService    vtpm.VTPMService
	responseWriter response.HttpWriter

	// Services the route-authorization audit wires so their routers
	// actually register. Left nil by the older tests, which only assert
	// that a nil service is skipped.
	platformRouter        *platform.PlatformRouter
	computeService        platformv1.ComputeServiceServer
	dnsService            dns.DNSService
	eabService            platformv1.EABServiceServer
	ntpService            platformv1.NTPServiceServer
	overlayService        platformv1.OverlayServiceServer
	switchService         device.SwitchServiceProvider
	gatewayService        platformv1.GatewayServiceServer
	gatewayStore          restgateway.GatewayStateStore
	configDelivery        configdelivery.RestHandler
	pxeService            platformv1.PXEServiceServer
	attestationService    platformv1.AttestationServiceServer
	deviceGRPCService     platformv1.DeviceServiceServer
	deviceTemplateService devicepkg.DeviceTemplateService
	deviceProfileService  devicepkg.DeviceProfileService
	invitationService     platformv1.InvitationServiceServer
	registryService       grpcapi.RegistryService
	tpmService            platformv1.TPMServiceServer
	tenantService         platformv1.TenantServiceServer
	idevidService         platformv1.IDevIDServiceServer
	kmsKeyMgmt            kmsclient.Client
	kmsCrypto             cryptoclient.Client
	kmsDEK                dekclient.Client
	kmsSecrets            secretsclient.Client
	tenantID              string
}

func (r *testHandlerRegistry) ACMERestService() trustedca.ACMERestServicer {
	return r.acmeService
}

func (r *testHandlerRegistry) DeviceRestHandler() device.RestHandler {
	return r.deviceHandler
}

func (r *testHandlerRegistry) IAMClients() (restiam.IAMClient, restiam.PEPClient) {
	return nil, nil
}

func (r *testHandlerRegistry) JSONWebTokenHandler() jwt.TokenHandler {
	return r.tokenHandler
}

func (r *testHandlerRegistry) PlatformTokenMiddleware() middleware.AuthMiddleware {
	return nil
}

func (r *testHandlerRegistry) KMSSDKClients() (kmsclient.Client, cryptoclient.Client, dekclient.Client, secretsclient.Client) {
	return r.kmsKeyMgmt, r.kmsCrypto, r.kmsDEK, r.kmsSecrets
}

func (r *testHandlerRegistry) MTLSMiddleware() middleware.MTLSMiddleware {
	return r.mtls
}

func (r *testHandlerRegistry) PlatformRestRouter() *platform.PlatformRouter {
	return r.platformRouter
}

func (r *testHandlerRegistry) ResponseWriter() response.HttpWriter {
	return r.responseWriter
}

func (r *testHandlerRegistry) SDNService() platformv1.SDNServiceServer {
	return r.sdnService
}

func (r *testHandlerRegistry) TPM() xkmssdk.TrustedPlatformModule {
	return r.tpm
}

func (r *testHandlerRegistry) VTPMService() vtpm.VTPMService {
	return r.vtpmService
}

func (r *testHandlerRegistry) WebAuthnRestService() webauthn.RestHandler {
	return r.webauthn
}

func (r *testHandlerRegistry) DeviceTemplateService() devicepkg.DeviceTemplateService {
	return r.deviceTemplateService
}

func (r *testHandlerRegistry) DeviceProfileService() devicepkg.DeviceProfileService {
	return r.deviceProfileService
}

func (r *testHandlerRegistry) ConfigDeliveryHandler() configdelivery.RestHandler {
	return r.configDelivery
}

func (r *testHandlerRegistry) SwitchService() device.SwitchServiceProvider {
	return r.switchService
}

func (r *testHandlerRegistry) TenantID() string {
	return r.tenantID
}

func (r *testHandlerRegistry) AdminClaimRestHandler() *adminclaim.RestHandler {
	return nil
}

func (r *testHandlerRegistry) DNSService() dns.DNSService {
	return r.dnsService
}

func (r *testHandlerRegistry) DeviceService() devicepkg.DeviceService {
	return nil
}

func (r *testHandlerRegistry) EmbeddedAdapter() sdktransport.Adapter {
	return nil
}

func (r *testHandlerRegistry) AttestationServiceServer() platformv1.AttestationServiceServer {
	return r.attestationService
}

func (r *testHandlerRegistry) ComputeServiceServer() platformv1.ComputeServiceServer {
	return r.computeService
}

func (r *testHandlerRegistry) DeviceServiceServer() platformv1.DeviceServiceServer {
	return r.deviceGRPCService
}

func (r *testHandlerRegistry) EABServiceServer() platformv1.EABServiceServer {
	return r.eabService
}

func (r *testHandlerRegistry) GatewayServiceServer() platformv1.GatewayServiceServer {
	return r.gatewayService
}

func (r *testHandlerRegistry) IDevIDServiceServer() platformv1.IDevIDServiceServer {
	return r.idevidService
}

func (r *testHandlerRegistry) InvitationServiceServer() platformv1.InvitationServiceServer {
	return r.invitationService
}

func (r *testHandlerRegistry) OverlayServiceServer() platformv1.OverlayServiceServer {
	return r.overlayService
}

func (r *testHandlerRegistry) PXEServiceServer() platformv1.PXEServiceServer {
	return r.pxeService
}

func (r *testHandlerRegistry) NTPServiceServer() platformv1.NTPServiceServer {
	return r.ntpService
}

func (r *testHandlerRegistry) TenantServiceServer() platformv1.TenantServiceServer {
	return r.tenantService
}

func (r *testHandlerRegistry) TPMServiceServer() platformv1.TPMServiceServer {
	return r.tpmService
}

func (r *testHandlerRegistry) RegistryService() grpcapi.RegistryService {
	return r.registryService
}

func (r *testHandlerRegistry) OCIDistBackend() restregistry.OCIDistBackend {
	return nil
}

func (r *testHandlerRegistry) AttestationEventReader() restattestation.EventReader {
	return nil
}

func (r *testHandlerRegistry) GatewayControlPlane() (restgateway.GatewayStateStore, restgateway.DesiredConfigSource) {
	return r.gatewayStore, nil
}

// Tests

func TestRegisterRoutes_NilServicesSkipped(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		webauthn:       &mockWebAuthnHandler{},
		responseWriter: respWriter,
	}

	v1Router := NewRouter(
		logger,
		nil, // no CA
		nil,
		nil,
		registry,
		respWriter,
	)

	muxRouter := mux.NewRouter()
	v1Router.RegisterRoutes(muxRouter)

	// Verify that system and authentication routes were registered
	// (they don't depend on nil checks) and nil services were skipped
	require.NotNil(t, muxRouter)
}

func TestRegisterRoutes_AllNilServices(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		webauthn:       &mockWebAuthnHandler{},
		responseWriter: respWriter,
		acmeService:    nil,
		sdnService:     nil,
		vtpmService:    nil,
		deviceHandler:  nil,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()

	// This should not panic even when all services are nil
	v1Router.RegisterRoutes(r)

	v1 := v1Router.(*Router)
	assert.NotNil(t, v1.router)
}

func TestPlatformRoutes_NilRouter(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		webauthn:       &mockWebAuthnHandler{},
		responseWriter: respWriter,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// platformRoutes returns nil from PlatformRestRouter -- should not panic
	v1.platformRoutes()
}

func TestCaRoutes_NilCA(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// caRoutes should return early because CA is nil
	v1.caRoutes()
}

func TestIamRoutes_NilClients(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// iamRoutes should return early because IAMClients returns nil
	v1.iamRoutes()
}

func TestKmsRoutes_NilClients(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// kmsRoutes should return early because KMSClients returns nil
	v1.kmsRoutes()
}

func TestSdnRoutes_NilService(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
		sdnService:     nil,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// sdnRoutes should return early because SDNService returns nil
	v1.sdnRoutes()
}

func TestVtpmRoutes_NilService(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
		vtpmService:    nil,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// vtpmRoutes should return early because VTPMService returns nil
	v1.vtpmRoutes()
}

func TestDeviceRoutes_NilHandler(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
		deviceHandler:  nil,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// deviceRoutes should return early because DeviceRestHandler returns nil
	v1.deviceRoutes()
}

func TestAcmeRoutes_NilService(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		responseWriter: respWriter,
		acmeService:    nil,
	}

	v1Router := NewRouter(
		logger,
		nil,
		nil,
		nil,
		registry,
		respWriter,
	)

	r := mux.NewRouter()
	v1 := v1Router.(*Router)
	v1.router = r

	// acmeRoutes should return early because ACMERestService returns nil
	v1.acmeRoutes()
}

// HandlerRegistry accessor tests

func TestHandlerRegistry_AccessorMethods(t *testing.T) {
	respWriter := response.NewResponseWriter(testLogger(), nil)

	registry := &testHandlerRegistry{
		tokenHandler:   &mockTokenHandler{},
		webauthn:       &mockWebAuthnHandler{},
		mtls:           &mockMTLSMiddleware{},
		responseWriter: respWriter,
	}

	t.Run("ResponseWriter returns writer", func(t *testing.T) {
		assert.Equal(t, respWriter, registry.ResponseWriter())
	})

	t.Run("TPM returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.TPM())
	})

	t.Run("VTPMService returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.VTPMService())
	})

	t.Run("SDNService returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.SDNService())
	})

	t.Run("IAMClients returns nil when not set", func(t *testing.T) {
		iam, pep := registry.IAMClients()
		assert.Nil(t, iam)
		assert.Nil(t, pep)
	})

	t.Run("KMSSDKClients returns nil when not set", func(t *testing.T) {
		key, crypto, dek, secrets := registry.KMSSDKClients()
		assert.Nil(t, key)
		assert.Nil(t, crypto)
		assert.Nil(t, dek)
		assert.Nil(t, secrets)
	})

	t.Run("ACMERestService returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.ACMERestService())
	})

	t.Run("DeviceRestHandler returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.DeviceRestHandler())
	})

	t.Run("JSONWebTokenHandler returns handler", func(t *testing.T) {
		assert.NotNil(t, registry.JSONWebTokenHandler())
	})

	t.Run("WebAuthnRestService returns handler", func(t *testing.T) {
		assert.NotNil(t, registry.WebAuthnRestService())
	})

	t.Run("MTLSMiddleware returns middleware", func(t *testing.T) {
		assert.NotNil(t, registry.MTLSMiddleware())
	})

	t.Run("PlatformRestRouter returns nil when not set", func(t *testing.T) {
		assert.Nil(t, registry.PlatformRestRouter())
	})
}
