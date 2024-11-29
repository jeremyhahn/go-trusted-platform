package service

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type Registry struct {
	deviceService          *device.Service
	dnsService             *dns.Service
	userService            UserServicer
	registrationService    RegistrationServicer
	webAuthnSessionService WebAuthnSessionServicer
}

func NewRegistry(
	logger *logging.Logger,
	deviceService *device.Service,
	dnsService *dns.Service,
	daoFactory datastore.Factory) (*Registry, error) {

	orgDAO, err := daoFactory.OrganizationDAO()
	if err != nil {
		return nil, err
	}

	regDAO, err := daoFactory.RegistrationDAO()
	if err != nil {
		return nil, err
	}

	roleDAO, err := daoFactory.RoleDAO()
	if err != nil {
		return nil, err
	}

	userDAO, err := daoFactory.UserDAO()
	if err != nil {
		return nil, err
	}

	webAuthnDAO, err := daoFactory.WebAuthnDAO()
	if err != nil {
		return nil, err
	}

	userService := NewUserService(
		logger,
		userDAO,
		orgDAO,
		roleDAO,
		nil)

	registrationService := NewRegistrationService(logger, regDAO)

	webAuthnSessionService := NewWebAuthnSessionService(logger, webAuthnDAO)

	return &Registry{
		deviceService:          deviceService,
		dnsService:             dnsService,
		userService:            userService,
		registrationService:    registrationService,
		webAuthnSessionService: webAuthnSessionService,
	}, err
}

func (registry *Registry) DeviceService() *device.Service {
	return registry.deviceService
}

func (registry *Registry) DNSService() *dns.Service {
	return registry.dnsService
}

func (registry *Registry) UserService() UserServicer {
	return registry.userService
}

func (registry *Registry) RegistrationService() RegistrationServicer {
	return registry.registrationService
}

func (registry *Registry) WebAuthnSessionService() WebAuthnSessionServicer {
	return registry.webAuthnSessionService
}
