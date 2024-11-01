package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Organization struct {
	ID             uint64 `yaml:"id" json:"id"`
	Name           string `yaml:"name" json:"name"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewOrganization(name string) *Organization {
	return &Organization{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (organization *Organization) SetEntityID(id uint64) {
	organization.ID = id
}

func (organization *Organization) EntityID() uint64 {
	return organization.ID
}
