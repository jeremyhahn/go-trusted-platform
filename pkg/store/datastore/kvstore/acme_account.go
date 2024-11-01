package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	acme_account_partition = "acme/accounts"
)

type ACMEAccountDAO struct {
	*AferoDAO[*entities.ACMEAccount]
}

func NewACMEAccountDAO(params *Params[*entities.ACMEAccount]) (datastore.ACMEAccountDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_account_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.ACMEAccount](params)
	if err != nil {
		return nil, err
	}
	return &ACMEAccountDAO{
		AferoDAO: aferoDAO,
	}, nil
}

// func (accountDAO *ACMEAccountDAO) Save(entity *entities.ACMEAccount) error {
// 	return accountDAO.AferoDAO.Save(entity)
// }

// func (accountDAO *ACMEAccountDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.ACMEAccount, error) {
// 	return accountDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
// }

// func (accountDAO *ACMEAccountDAO) Delete(entity *entities.ACMEAccount) error {
// 	return accountDAO.AferoDAO.Delete(entity)
// }

// func (accountDAO *ACMEAccountDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
// 	return accountDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
// }

// func (accountDAO *ACMEAccountDAO) Page(
// 	pageQuery datastore.PageQuery,
// 	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.ACMEAccount], error) {

// 	return accountDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
// }

// func (accountDAO *ACMEAccountDAO) ForEachPage(
// 	pageQuery datastore.PageQuery,
// 	pagerProcFunc datastore.PagerProcFunc[*entities.ACMEAccount],
// 	CONSISTENCY_LEVEL int) error {

// 	return accountDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
// }
