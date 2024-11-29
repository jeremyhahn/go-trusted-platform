package afero

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

	accountID := uint64(1)

	factory, err := NewFactory(logger, config)
	assert.Nil(t, err)

	acmeAccountDAO, err := factory.ACMEAccountDAO()
	assert.Nil(t, err)
	assert.IsType(t, &ACMEAccountDAO{}, acmeAccountDAO)

	acmeOrderDAO, err := factory.ACMEOrderDAO(accountID)
	assert.Nil(t, err)
	assert.IsType(t, &ACMEOrderDAO{}, acmeOrderDAO)

	acmeChallengeDAO, err := factory.ACMEChallengeDAO(accountID)
	assert.Nil(t, err)
	assert.IsType(t, &ACMEChallengeDAO{}, acmeChallengeDAO)

	acmeAuthorizationDAO, err := factory.ACMEAuthorizationDAO(accountID)
	assert.Nil(t, err)
	assert.IsType(t, &ACMEAuthorizationDAO{}, acmeAuthorizationDAO)

	acmeCertificateDAO, err := factory.ACMECertificateDAO()
	assert.Nil(t, err)
	assert.IsType(t, &ACMECertificateDAO{}, acmeCertificateDAO)

	acmeNonceDAO, err := factory.ACMENonceDAO()
	assert.Nil(t, err)
	assert.IsType(t, &ACMENonceDAO{}, acmeNonceDAO)
}
