package entities

type ACMEOrder struct {
	ID             uint64           `yaml:"id" json:"id"`
	Status         string           `yaml:"status" json:"status"`
	Expires        string           `yaml:"expires" json:"expires,omitempty"`
	Identifiers    []ACMEIdentifier `yaml:"identifiers" json:"identifiers"`
	NotBefore      string           `yaml:"not-before" json:"notBefore,omitempty"`
	NotAfter       string           `yaml:"not-after" json:"notAfter,omitempty"`
	Error          *Error           `yaml:"error" json:"error,omitempty"`
	Authorizations []string         `yaml:"authorizations" json:"authorizations"`
	Finalize       string           `yaml:"finalize" json:"finalize"`
	Certificate    string           `yaml:"certificate" json:"certificate,omitempty"`
	CertificateURL string           `yaml:"certificate-url" json:"certificate_url,omitempty"`
	XSignedOrder   *ACMEOrder       `yaml:"x-signed-order" json:"x-signed-order,omitempty"`
	AccountID      uint64           `yaml:"account-id" json:"account_id"`
	URL            string           `yaml:"url" json:"url"`
}

func (order *ACMEOrder) SetEntityID(id uint64) {
	order.ID = id
}

func (order *ACMEOrder) EntityID() uint64 {
	return order.ID
}
