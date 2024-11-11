package entities

import "time"

type ACMEAccount struct {
	ID                     uint64      `yaml:"id" json:"id"`
	Contact                []string    `yaml:"contact" json:"contact,omitempty"`
	CreatedAt              time.Time   `yaml:"created" json:"created"`
	ExternalAccountBinding interface{} `yaml:"externalAccountBinding" json:"externalAccountBinding,omitempty"`
	Key                    string      `yaml:"key" json:"key"`
	OnlyReturnExisting     bool        `yaml:"onlyReturnExisting" json:"onlyReturnExisting,omitempty"`
	Orders                 string      `yaml:"orders" json:"orders"`
	Status                 string      `yaml:"status" json:"status"`
	TermsOfServiceAgreed   bool        `yaml:"termsOfServiceAgreed" json:"termsOfServiceAgreed,omitempty"`
	URL                    string      `yaml:"url" json:"url"`
}

func (account *ACMEAccount) SetEntityID(id uint64) {
	account.ID = id
}

func (account *ACMEAccount) EntityID() uint64 {
	return account.ID
}
