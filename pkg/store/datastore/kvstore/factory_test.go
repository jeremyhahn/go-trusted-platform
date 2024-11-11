package kvstore

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
)

func TestInterfaces(t *testing.T) {

	logger := logging.DefaultLogger()

	config := &datastore.Config{
		Backend:          datastore.BackendAferoMemory.String(),
		ConsistencyLevel: "local",
		ReadBufferSize:   50,
		RootDir:          "./",
		Serializer:       serializer.SERIALIZER_JSON.String(),
	}

	factory, err := New(logger, config)
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

	webAuthnDAO, err := factory.WebAuthnDAO()
	assert.Nil(t, err)
	assert.IsType(t, &WebAuthnDAO{}, webAuthnDAO)

	// accountID := uint64(1)

	// acmeAccountDAO, err := factory.ACMEAccountDAO()
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMEAccountDAO{}, acmeAccountDAO)

	// acmeOrderDAO, err := factory.ACMEOrderDAO(accountID)
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMEOrderDAO{}, acmeOrderDAO)

	// acmeChallengeDAO, err := factory.ACMEChallengeDAO(accountID)
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMEChallengeDAO{}, acmeChallengeDAO)

	// acmeAuthorizationDAO, err := factory.ACMEAuthorizationDAO(accountID)
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMEAuthorizationDAO{}, acmeAuthorizationDAO)

	// acmeCertificateDAO, err := factory.ACMECertificateDAO()
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMECertificateDAO{}, acmeCertificateDAO)

	// acmeNonceDAO, err := factory.ACMENonceDAO()
	// assert.Nil(t, err)
	// assert.IsType(t, &ACMENonceDAO{}, acmeNonceDAO)
}
