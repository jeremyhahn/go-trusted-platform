package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	webauthn_partition = "webauthn"
)

type WebAuthnDAO struct {
	*AferoDAO[*entities.Blob]
}

func NewWebAuthnDAO(params *Params[*entities.Blob]) (datastore.WebAuthnDAO, error) {
	if params.Partition == "" {
		params.Partition = webauthn_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.Blob](params)
	if err != nil {
		return nil, err
	}
	return &WebAuthnDAO{
		AferoDAO: aferoDAO,
	}, nil
}

// func (webauthnDAO *WebAuthnDAO) Save(entity *entities.Blob) error {
// 	return webauthnDAO.AferoDAO.Save(entity)
// }

// func (webauthnDAO *WebAuthnDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.Blob, error) {
// 	return webauthnDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
// }

// func (webauthnDAO *WebAuthnDAO) Delete(entity *entities.Blob) error {
// 	return webauthnDAO.AferoDAO.Delete(entity)
// }

// func (webauthnDAO *WebAuthnDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
// 	return webauthnDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
// }

// func (webauthnDAO *WebAuthnDAO) Page(
// 	pageQuery datastore.PageQuery,
// 	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.Blob], error) {

// 	return webauthnDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
// }

// func (webauthnDAO *WebAuthnDAO) ForEachPage(
// 	pageQuery datastore.PageQuery,
// 	pagerProcFunc datastore.PagerProcFunc[*entities.Blob],
// 	CONSISTENCY_LEVEL int) error {

// 	return webauthnDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
// }
