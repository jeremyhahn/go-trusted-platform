package acme

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao/afero"
)

// Returns an ACME datastore using the backend specified in the datastore section of the
// platform configuration file
func NewDatastore(logger *logging.Logger, config *datastore.Config) (dao.Factory, error) {
	switch config.Backend {
	case datastore.BackendAferoFS.String(), datastore.BackendAferoMemory.String():
		return afero.NewFactory(logger, config)
	default:
		return nil, datastore.ErrInvalidBackend
	}
}
