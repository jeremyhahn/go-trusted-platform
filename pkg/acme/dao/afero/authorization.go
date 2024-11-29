package afero

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	acme_authorization_partition = "acme/authorizations"
	// acme_authorization_url_index = "url"
)

type ACMEAuthorizationDAO struct {
	params *datastore.Params[*entities.ACMEAuthorization]
	*kvstore.AferoDAO[*entities.ACMEAuthorization]
}

func NewACMEAuthorizationDAO(params *datastore.Params[*entities.ACMEAuthorization], accountID uint64) (dao.ACMEAuthorizationDAO, error) {
	params.Partition = fmt.Sprintf("acme/%d/authorizations", accountID)
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMEAuthorizationDAO{
		AferoDAO: aferoDAO,
		params:   params,
	}, nil
}

// func (authorizationDAO *ACMEAuthorizationDAO) Save(entity *entities.ACMEAuthorization) error {
// 	if entity.URL != "" {
// 		idx := entities.NewPropertyIndex(acme_authorization_url_index, 0, []byte(entity.URL))
// 		indexDAO, err := authorizationDAO.urlIndexDAO()
// 		if err != nil {
// 			return err
// 		}
// 		if err := indexDAO.Save(idx.(*entities.Reference)); err != nil {
// 			return err
// 		}
// 	}
// 	return authorizationDAO.AferoDAO.Save(entity)
// }

// func (authorizationDAO *ACMEAuthorizationDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.ACMEAuthorization, error) {
// 	return authorizationDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
// }

// func (authorizationDAO *ACMEAuthorizationDAO) Delete(entity *entities.ACMEAuthorization) error {
// 	if entity.URL != "" {
// 		idx := entities.NewPropertyIndex(acme_authorization_url_index, 0, []byte(entity.URL))
// 		indexDAO, err := authorizationDAO.urlIndexDAO()
// 		if err != nil {
// 			return err
// 		}
// 		if err := indexDAO.Delete(idx.(*entities.Reference)); err != nil {
// 			return err
// 		}
// 	}
// 	return authorizationDAO.AferoDAO.Delete(entity)
// }

// func (authorizationDAO *ACMEAuthorizationDAO) GetAuthorizationByURL(url string, CONSISTENCY_LEVEL int) (*entities.ACMEAuthorization, error) {

// 	indexDAO, err := authorizationDAO.urlIndexDAO()

// 	idx := entities.NewPropertyIndex(acme_authorization_url_index, 0, []byte(url))
// 	index, err := indexDAO.Get(idx.EntityID(), CONSISTENCY_LEVEL)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return authorizationDAO.Get(index.RefID(), CONSISTENCY_LEVEL)
// }

// func (authorizationDAO *ACMEAuthorizationDAO) urlIndexDAO() (datastore.GenericDAO[*entities.Reference], error) {

// 	serializerType := authorizationDAO.params.Serializer.Type()
// 	serializer, err := serializer.NewSerializer[*entities.Reference](serializerType)
// 	if err != nil {
// 		return nil, err
// 	}
// 	params := &Params[*entities.Reference]{
// 		Fs:             authorizationDAO.params.Fs,
// 		Logger:         authorizationDAO.params.Logger,
// 		Partition:      fmt.Sprintf("%s/%s", acme_authorization_partition, acme_authorization_url_index),
// 		ReadBufferSize: authorizationDAO.readBufferSize,
// 		RootDir:        authorizationDAO.params.RootDir,
// 		Serializer:     serializer}
// 	aferoDAO, err := NewAferoDAO(params)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return aferoDAO, nil
// }
