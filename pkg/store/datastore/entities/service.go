package entities

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

type Service struct {
	ID            uint64
	Name          string
	KeyAttributes *keystore.KeyAttributes
}

func NewService(name string) *Service {
	return &Service{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (service *Service) SetEntityID(id uint64) {
	service.ID = id
}

func (service *Service) EntityID() uint64 {
	return service.ID
}

func (service *Service) Partition() string {
	return "services"
}
