package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrCreateService            = errors.New("service: failed to create service")
	ErrPermissionDenied         = errors.New("service: permission denied")
	ErrDeleteAdminAccount       = errors.New("service: admin account can't be deleted")
	ErrChangeAdminRole          = errors.New("service: admin role can't be changed")
	ErrResetPasswordUnsupported = errors.New("service: reset password feature unsupported by auth store")
)

type UserCredential struct {
	OrgID    uint64 `json:"org"`
	Email    string `json:"email"`
	Password string `json:"password"`
	AuthType int    `json:"authType"`
}

// Claim structs are condensed models concerned only
// with users, roles, permissions, and licensing between
// the client and server. They get exchanged with every
// request and are used to generate a "Session" for working
// with business logic services in the "service" package.
// type ServiceClaim struct {
// 	ID    uint64   `json:"id"`
// 	Name  string   `json:"name"`
// 	Roles []string `json:"roles"`
// }

// type OrganizationClaim struct {
// 	ID       uint64         `json:"id"`
// 	Name     string         `json:"name"`
// 	Services []ServiceClaim `json:"farms"`
// 	Roles    []string       `json:"roles"`
// }

type AuthServicer interface {
	Activate(registrationID uint64) (*entities.User, error)
	Login(userCredentials *UserCredential) (*entities.User, []*entities.Organization, []*entities.Service, error)
	Register(userCredentials *UserCredential, baseURI string) (*entities.User, error)
	ResetPassword(userCredentials *UserCredential) error
}
