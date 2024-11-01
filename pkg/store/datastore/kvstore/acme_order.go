package kvstore

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	acme_order_partition = "acme/%d/orders"
)

type ACMEOrderDAO struct {
	params *Params[*entities.ACMEOrder]
	*AferoDAO[*entities.ACMEOrder]
}

func NewACMEOrderDAO(params *Params[*entities.ACMEOrder], accountID uint64) (datastore.ACMEOrderDAO, error) {
	params.Partition = fmt.Sprintf("acme/%d/orders", accountID)
	aferoDAO, err := NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMEOrderDAO{
		AferoDAO: aferoDAO,
		params:   params,
	}, nil
}

func (orderDAO *ACMEOrderDAO) GetByAccountID(
	accountID uint64,
	CONSISTENCY_LEVEL datastore.ConsistencyLevel) (datastore.PageResult[*entities.ACMEOrder], error) {

	params := *orderDAO.params
	params.Partition = fmt.Sprintf(acme_order_partition, accountID)
	aferoDAO, err := NewAferoDAO(&params)
	if err != nil {
		return datastore.PageResult[*entities.ACMEOrder]{}, err
	}
	pageQuery := datastore.NewPageQuery()

	return aferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
}
