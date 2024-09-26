package kvstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactory(t *testing.T) {

	params := aferoTestParams()
	factory, err := NewFactory(params)
	assert.Nil(t, err)

	orgDAO, err := factory.OrganizationDAO()
	assert.Nil(t, err)
	assert.IsType(t, &OrganizationDAO{}, orgDAO)

	regDAO, err := factory.RegistrationDAO()
	assert.Nil(t, err)
	assert.IsType(t, &RegistrationDAO{}, regDAO)

	roleDAO, err := factory.RoleDAO()
	assert.Nil(t, err)
	assert.IsType(t, &RoleDAO{}, roleDAO)

	userDAO, err := factory.UserDAO()
	assert.Nil(t, err)
	assert.IsType(t, &UserDAO{}, userDAO)
}
