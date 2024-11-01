package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Registration struct {
	ID             uint64 `yaml:"id" json:"id"`
	Email          string `yaml:"email" json:"email"`
	Password       string `yaml:"password" json:"password"`
	OrgID          uint64 `yaml:"org-id" json:"org_id"`
	OrgName        string `yaml:"org-name" json:"org_name"`
	SessionData    []byte `yaml:"session-data" json:"session_data"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewRegistration(email string) *Registration {
	return &Registration{
		ID:    util.NewID([]byte(email)),
		Email: email,
	}
}

func (r *Registration) EntityID() uint64 {
	return r.ID
}

func (r *Registration) SetEntityID(id uint64) {
	r.ID = id
}
