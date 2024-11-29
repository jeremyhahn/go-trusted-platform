package acme

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao/afero"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
)

func TestBackends(t *testing.T) {

	logger := logging.DefaultLogger()

	backends := []string{
		datastore.BackendAferoMemory.String(),
		datastore.BackendAferoFS.String(),
	}

	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) {
			config := &datastore.Config{
				Backend:          backend,
				ConsistencyLevel: "local",
				ReadBufferSize:   50,
				RootDir:          "./",
				Serializer:       serializer.SERIALIZER_JSON.String(),
			}

			accountID := uint64(1)

			factory, err := NewDatastore(logger, config)
			assert.Nil(t, err)

			acmeAccountDAO, err := factory.ACMEAccountDAO()
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMEAccountDAO{}, acmeAccountDAO)

			acmeOrderDAO, err := factory.ACMEOrderDAO(accountID)
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMEOrderDAO{}, acmeOrderDAO)

			acmeChallengeDAO, err := factory.ACMEChallengeDAO(accountID)
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMEChallengeDAO{}, acmeChallengeDAO)

			acmeAuthorizationDAO, err := factory.ACMEAuthorizationDAO(accountID)
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMEAuthorizationDAO{}, acmeAuthorizationDAO)

			acmeCertificateDAO, err := factory.ACMECertificateDAO()
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMECertificateDAO{}, acmeCertificateDAO)

			acmeNonceDAO, err := factory.ACMENonceDAO()
			assert.Nil(t, err)
			assert.IsType(t, &afero.ACMENonceDAO{}, acmeNonceDAO)
		})
	}
}
