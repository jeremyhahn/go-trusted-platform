package rest

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/acme"
)

type RestRegistry struct {
	acmeRestService     acme.RestServicer
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

func NewHandlerRegistry(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	daoFactory datastore.Factory,
	serverKeyAttributes *keystore.KeyAttributes,
	serviceRegistry *service.Registry,
	config *config.WebService,
	jwtClaimsIssuer string) RestServiceRegistry {

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

	acmeRestService, err := acme.NewRestService(
		config.Certificate.Subject.CommonName,
		daoFactory,
		ca,
		logger,
		config,
		datastore.CONSISTENCY_LOCAL)
	if err != nil {
		logger.FatalError(err)
	}

	systemService := NewSystemRestService(
		ca,
		serverKeyAttributes,
		httpWriter,
		logger)

	webAuthnRestService, err := NewWebAuthnRestService(
		logger,
		config,
		httpWriter,
		jwtService,
		serviceRegistry.UserService(),
		serviceRegistry.RegistrationService(),
		serviceRegistry.WebAuthnSessionService())

	return &RestRegistry{
		acmeRestService:     acmeRestService,
		jsonWebTokenService: jsonWebTokenService,
		serviceRegistry:     serviceRegistry,
		systemRestService:   systemService,
		webauthnRestService: webAuthnRestService,
	}
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

func (registry *RestRegistry) ACMERestService() acme.RestServicer {
	return registry.acmeRestService
}
