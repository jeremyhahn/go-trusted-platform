package kvstore

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"

type Factory struct {
	params *Params
	datastore.Factory
}

func NewFactory(params *Params) (datastore.Factory, error) {
	return &Factory{params: params}, nil
}

func (factory *Factory) OrganizationDAO() (datastore.OrganizationDAO, error) {
	params := *factory.params
	return NewOrganizationDAO(&params)
}

func (factory *Factory) UserDAO() (datastore.UserDAO, error) {
	params := *factory.params
	return NewUserDAO(&params)
}

func (factory *Factory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	params := *factory.params
	return NewRegistrationDAO(&params)
}

func (factory *Factory) RoleDAO() (datastore.RoleDAO, error) {
	params := *factory.params
	return NewRoleDAO(&params)
}

func (factory *Factory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	params := *factory.params
	return NewWebAuthnDAO(&params)
}
