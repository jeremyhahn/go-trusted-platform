package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"

type Device struct {
	ID uint64 `yaml:"id" json:"id"`

	AttestPub  string `yaml:"att-pub" json:"att_pub"`
	EKCert     string `yaml:"ek-cert" json:"ek_cert"`
	EventLog   []byte `yaml:"event-log" json:"event_log"`
	HashAlgoId uint32 `yaml:"hash-algo" json:"hash_algo"`
	Model      string `yaml:"model" json:"model"`
	Serial     string `yaml:"serial" json:"serial"`
	SigningPub string `yaml:"signing-pub" json:"signing_pub"`

	entities.KeyValueEntity `yaml:"-" json:"-"`
}

func (d *Device) EntityID() uint64 {
	return d.ID
}

func (d *Device) SetEntityID(id uint64) {
	d.ID = id
}
