package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	acme_nonce_partition = "acme/nonces"
)

type ACMENonceDAO struct {
	*AferoDAO[*entities.ACMENonce]
}

func NewACMENonceDAO(params *Params[*entities.ACMENonce]) (datastore.ACMENonceDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_nonce_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.ACMENonce](params)
	if err != nil {
		return nil, err
	}
	return &ACMENonceDAO{
		AferoDAO: aferoDAO,
	}, nil
}
