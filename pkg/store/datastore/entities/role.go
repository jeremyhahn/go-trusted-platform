package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Role struct {
	ID             uint64 `json:"id"`
	Name           string `json:"name"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewRole(name string) *Role {
	return &Role{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (role *Role) SetEntityID(id uint64) {
	role.ID = id
}

func (role *Role) EntityID() uint64 {
	return role.ID
}
