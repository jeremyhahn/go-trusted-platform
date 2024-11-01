package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	organization_partition = "organizations"
)

type OrganizationDAO struct {
	*AferoDAO[*entities.Organization]
}

func NewOrganizationDAO(params *Params[*entities.Organization]) (datastore.OrganizationDAO, error) {
	if params.Partition == "" {
		params.Partition = organization_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.Organization](params)
	if err != nil {
		return nil, err
	}
	return &OrganizationDAO{
		AferoDAO: aferoDAO,
	}, nil
}

// func (organizationDAO *OrganizationDAO) Save(entity *entities.Organization) error {
// 	return organizationDAO.AferoDAO.Save(entity)
// }

// func (organizationDAO *OrganizationDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.Organization, error) {
// 	return organizationDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
// }

// func (organizationDAO *OrganizationDAO) Delete(entity *entities.Organization) error {
// 	return organizationDAO.AferoDAO.Delete(entity)
// }

// func (organizationDAO *OrganizationDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
// 	return organizationDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
// }

// func (organizationDAO *OrganizationDAO) Page(
// 	pageQuery datastore.PageQuery,
// 	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.Organization], error) {

// 	return organizationDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
// }

// func (organizationDAO *OrganizationDAO) ForEachPage(
// 	pageQuery datastore.PageQuery,
// 	pagerProcFunc datastore.PagerProcFunc[*entities.Organization],
// 	CONSISTENCY_LEVEL int) error {

// 	return organizationDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
// }

func (organizationDAO *OrganizationDAO) GetUsers(id uint64, CONSISTENCY_LEVEL datastore.ConsistencyLevel) ([]*entities.User, error) {
	// org, err := organizationDAO.Get(id, CONSISTENCY_LEVEL)
	// if err != nil {
	// 	return nil, err
	// }
	// aggRoot, err := entities.NewAggregateRoot(org, organization_partition, nil, user_partition)
	// if err != nil {
	// 	return nil, err
	// }
	return nil, nil
}
