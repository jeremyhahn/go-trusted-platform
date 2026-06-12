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

package service

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

type Registry struct {
	deviceService          *device.Service
	profileService         *device.ProfileService
	templateService        *device.TemplateService
	dnsService             *dns.Service
	userService            UserServicer
	registrationService    RegistrationServicer
	webAuthnSessionService WebAuthnSessionServicer
	invitationService      InvitationServicer
	tenantUserService      TenantUserServicer
}

// RegistryConfig holds configuration for creating a Registry.
type RegistryConfig struct {
	Logger          *logging.Logger
	DeviceService   *device.Service
	ProfileService  *device.ProfileService
	TemplateService *device.TemplateService
	DNSService      *dns.Service
	DAOFactory      datastore.Factory
	TenantManager   *tenant.Manager
	TokenIssuer     TokenIssuer
}

func NewRegistry(
	logger *logging.Logger,
	deviceService *device.Service,
	profileService *device.ProfileService,
	templateService *device.TemplateService,
	dnsService *dns.Service,
	daoFactory datastore.Factory) (*Registry, error) {

	return NewRegistryWithConfig(&RegistryConfig{
		Logger:          logger,
		DeviceService:   deviceService,
		ProfileService:  profileService,
		TemplateService: templateService,
		DNSService:      dnsService,
		DAOFactory:      daoFactory,
		TenantManager:   nil,
		TokenIssuer:     nil,
	})
}

// NewRegistryWithConfig creates a new Registry with full configuration options.
func NewRegistryWithConfig(config *RegistryConfig) (*Registry, error) {
	regDAO, err := config.DAOFactory.RegistrationDAO()
	if err != nil {
		return nil, err
	}

	roleDAO, err := config.DAOFactory.RoleDAO()
	if err != nil {
		return nil, err
	}

	userDAO, err := config.DAOFactory.UserDAO()
	if err != nil {
		return nil, err
	}

	webAuthnDAO, err := config.DAOFactory.WebAuthnDAO()
	if err != nil {
		return nil, err
	}

	userService := NewUserService(
		config.Logger,
		userDAO,
		roleDAO,
		nil)

	registrationService := NewRegistrationService(config.Logger, regDAO)

	webAuthnSessionService := NewWebAuthnSessionService(config.Logger, webAuthnDAO)

	// Initialize invitation service if DAO is available
	var invitationService InvitationServicer
	invitationDAO, err := config.DAOFactory.InvitationDAO()
	if err == nil && invitationDAO != nil {
		invitationService = NewInvitationService(config.Logger, invitationDAO, userDAO)
	}

	// Initialize tenant user service if tenant manager and invitation service are available
	var tenantUserService TenantUserServicer
	if config.TenantManager != nil && invitationService != nil {
		tenantUserService = NewTenantUserService(&TenantUserServiceConfig{
			Logger:            config.Logger,
			UserService:       userService,
			InvitationService: invitationService,
			TenantManager:     config.TenantManager,
			TokenIssuer:       config.TokenIssuer,
		})
	}

	return &Registry{
		deviceService:          config.DeviceService,
		profileService:         config.ProfileService,
		templateService:        config.TemplateService,
		dnsService:             config.DNSService,
		userService:            userService,
		registrationService:    registrationService,
		webAuthnSessionService: webAuthnSessionService,
		invitationService:      invitationService,
		tenantUserService:      tenantUserService,
	}, nil
}

func (registry *Registry) ProfileService() *device.ProfileService {
	return registry.profileService
}

// TemplateService returns the device template service.
func (registry *Registry) TemplateService() *device.TemplateService {
	return registry.templateService
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

func (registry *Registry) InvitationService() InvitationServicer {
	return registry.invitationService
}

func (registry *Registry) TenantUserService() TenantUserServicer {
	return registry.tenantUserService
}

// SetTenantUserService allows setting the tenant user service after initialization.
// This is useful when the tenant manager is initialized after the registry.
func (registry *Registry) SetTenantUserService(tenantUserService TenantUserServicer) {
	registry.tenantUserService = tenantUserService
}

// SetInvitationService allows setting the invitation service after initialization.
func (registry *Registry) SetInvitationService(invitationService InvitationServicer) {
	registry.invitationService = invitationService
}
