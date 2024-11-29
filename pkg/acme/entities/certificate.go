package entities

import "time"

type ACMECertificate struct {
	ID        uint64    `yaml:"id" json:"id"`
	CertURL   string    `yaml:"cert-url"  json:"cert_url"`
	PEM       string    `yaml:"pem" json:"pem"`
	IssuedAt  time.Time `yaml:"issued" json:"issued"`
	Status    string    `yaml:"status" json:"status"`
	ExpiresAt time.Time `yaml:"expires" json:"expires"`
}

func (cert *ACMECertificate) SetEntityID(id uint64) {
	cert.ID = id
}

func (cert *ACMECertificate) EntityID() uint64 {
	return cert.ID
}
