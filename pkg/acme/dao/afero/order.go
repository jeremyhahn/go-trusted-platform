package afero

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	acme_order_partition = "acme/%d/orders"
)

type ACMEOrderDAO struct {
	accountID uint64
	params    *datastore.Params[*entities.ACMEOrder]
	*kvstore.AferoDAO[*entities.ACMEOrder]
}

func NewACMEOrderDAO(
	params *datastore.Params[*entities.ACMEOrder],
	accountID uint64) (dao.ACMEOrderDAO, error) {

	params.Partition = fmt.Sprintf("acme/%d/orders", accountID)
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMEOrderDAO{
		accountID: accountID,
		AferoDAO:  aferoDAO,
		params:    params,
	}, nil
}

func (orderDAO *ACMEOrderDAO) GetByAccountID(CONSISTENCY_LEVEL datastore.ConsistencyLevel) (datastore.PageResult[*entities.ACMEOrder], error) {

	params := *orderDAO.params
	params.Partition = fmt.Sprintf(acme_order_partition, orderDAO.accountID)
	aferoDAO, err := kvstore.NewAferoDAO(&params)
	if err != nil {
		return datastore.PageResult[*entities.ACMEOrder]{}, err
	}
	pageQuery := datastore.NewPageQuery()

	return aferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
}
