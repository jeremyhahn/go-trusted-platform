package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	user_partition = "users"
)

type UserDAO struct {
	*AferoDAO[*entities.User]
}

func NewUserDAO(params *datastore.Params[*entities.User]) (datastore.UserDAO, error) {
	if params.Partition == "" {
		params.Partition = user_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.User](params)
	if err != nil {
		return nil, err
	}
	return &UserDAO{
		AferoDAO: aferoDAO,
	}, nil
}
