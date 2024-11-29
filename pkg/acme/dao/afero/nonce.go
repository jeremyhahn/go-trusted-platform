package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	acme_nonce_partition = "acme/nonces"
)

type ACMENonceDAO struct {
	*kvstore.AferoDAO[*entities.ACMENonce]
}

func NewACMENonceDAO(params *datastore.Params[*entities.ACMENonce]) (dao.ACMENonceDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_nonce_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO[*entities.ACMENonce](params)
	if err != nil {
		return nil, err
	}
	return &ACMENonceDAO{
		AferoDAO: aferoDAO,
	}, nil
}
