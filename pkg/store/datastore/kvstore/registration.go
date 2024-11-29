package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	registration_partition = "registrations"
)

type RegistrationDAO struct {
	*AferoDAO[*entities.Registration]
}

func NewRegistrationDAO(params *datastore.Params[*entities.Registration]) (datastore.RegistrationDAO, error) {
	if params.Partition == "" {
		params.Partition = registration_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.Registration](params)
	if err != nil {
		return nil, err
	}
	return &RegistrationDAO{
		AferoDAO: aferoDAO,
	}, nil
}

// func (registrationDAO *RegistrationDAO) Save(entity *entities.Registration) error {
// 	return registrationDAO.AferoDAO.Save(entity)
// }

// func (registrationDAO *RegistrationDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.Registration, error) {
// 	return registrationDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
// }

// func (registrationDAO *RegistrationDAO) Delete(entity *entities.Registration) error {
// 	return registrationDAO.AferoDAO.Delete(entity)
// }

// func (registrationDAO *RegistrationDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
// 	return registrationDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
// }

// func (registrationDAO *RegistrationDAO) Page(
// 	pageQuery datastore.PageQuery,
// 	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.Registration], error) {

// 	return registrationDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
// }

// func (registrationDAO *RegistrationDAO) ForEachPage(
// 	pageQuery datastore.PageQuery,
// 	pagerProcFunc datastore.PagerProcFunc[*entities.Registration],
// 	CONSISTENCY_LEVEL int) error {

// 	return registrationDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
// }
