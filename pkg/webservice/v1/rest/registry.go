package rest

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

type RestRegistry struct {
	claimsIssuer        string
	jwtExpiration       int
	logger              *logging.Logger
	jsonWebTokenService JsonWebTokenServicer
	serviceRegistry     *service.Registry
	systemRestService   SystemRestServicer
	webauthnRestService WebAuthnRestServicer
	endpointList        *[]string
	RestServiceRegistry
}

func NewRestServiceRegistry(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes,
	serviceRegistry *service.Registry,
	config *config.WebService,
	jwtClaimsIssuer string) RestServiceRegistry {

	endpointList := make([]string, 0)

	httpWriter := response.NewResponseWriter(logger, nil)

	jwtService, err := jwt.NewService(config, ca.Keyring(), serverKeyAttributes)
	if err != nil {
		logger.FatalError(err)
	}

	jsonWebTokenService, err := NewJsonWebTokenRestService(
		logger,
		httpWriter,
		jwtService,
		serviceRegistry.UserService())
	if err != nil {
		logger.FatalError(err)
	}

	webAuthnRestService, err := NewWebAuthnRestService(
		logger,
		config,
		httpWriter,
		jwtService,
		serviceRegistry.UserService(),
		serviceRegistry.RegistrationService(),
		serviceRegistry.WebAuthnSessionService())

	registry := &RestRegistry{
		endpointList:        &endpointList,
		jsonWebTokenService: jsonWebTokenService,
		serviceRegistry:     serviceRegistry,
		webauthnRestService: webAuthnRestService,
	}

	registry.systemRestService = NewSystemRestService(
		ca,
		serverKeyAttributes,
		httpWriter,
		logger,
		registry.endpointList)

	return registry
}

func (registry *RestRegistry) JsonWebTokenService() JsonWebTokenServicer {
	return registry.jsonWebTokenService
}

func (registry *RestRegistry) SystemRestService() SystemRestServicer {
	return registry.systemRestService
}

func (registry *RestRegistry) WebAuthnRestService() WebAuthnRestServicer {
	return registry.webauthnRestService
}
