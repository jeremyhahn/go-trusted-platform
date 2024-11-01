package entities

import "time"

type ACMEAccount struct {
	ID                     uint64      `yaml:"id" json:"id"`
	Status                 string      `yaml:"status" json:"status"`
	Contact                []string    `yaml:"contact" json:"contact,omitempty"`
	TermsOfServiceAgreed   bool        `yaml:"termsOfServiceAgreed" json:"termsOfServiceAgreed,omitempty"`
	ExternalAccountBinding interface{} `yaml:"externalAccountBinding" json:"externalAccountBinding,omitempty"`
	OnlyReturnExisting     bool        `yaml:"onlyReturnExisting" json:"onlyReturnExisting,omitempty"`
	Orders                 string      `yaml:"orders" json:"orders"`
	Key                    string      `yaml:"key" json:"key"`
	CreatedAt              time.Time   `yaml:"created" json:"created"`
}

func (account *ACMEAccount) SetEntityID(id uint64) {
	account.ID = id
}

func (account *ACMEAccount) EntityID() uint64 {
	return account.ID
}
