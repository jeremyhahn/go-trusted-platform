package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type User struct {
	ID               uint64   `json:"id"`
	Email            string   `json:"email"`
	Password         string   `json:"password"`
	Roles            []*Role  `json:"roles"`
	OrganizationRefs []uint64 `json:"orgs"`
	ServiceRefs      []uint64 `json:"services"`
	KeyValueEntity
}

func NewUser(email string) *User {
	return &User{
		ID:    util.NewID([]byte(email)),
		Email: email,
		Roles: make([]*Role, 0)}
}

func (user *User) SetEntityID(id uint64) {
	user.ID = id
}

func (user *User) EntityID() uint64 {
	return user.ID
}

func (user *User) Partition() string {
	return "users"
}

func (user *User) AddRole(role *Role) {
	user.Roles = append(user.Roles, role)
}

func (user *User) HasRole(name string) bool {
	for _, role := range user.Roles {
		if role.Name == name {
			return true
		}
	}
	return false
}
