package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Registration struct {
	ID       uint64 `gorm:"primaryKey" yaml:"id" json:"id"`
	Email    string `yaml:"email" json:"email"`
	Password string `yaml:"password" json:"password"`
	OrgID    uint64 `yaml:"org_id" json:"org_id"`
	OrgName  string `yaml:"org_name" json:"org_name"`
	KeyValueEntity
}

func NewRegistration(email string) *Registration {
	return &Registration{
		ID:    util.NewID([]byte(email)),
		Email: email,
	}
}

func (r *Registration) Partition() string {
	return "registrations"
}

func (r *Registration) EntityID() uint64 {
	return r.ID
}

func (r *Registration) SetEntityID(id uint64) {
	r.ID = id
}
