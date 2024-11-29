package acme

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type Config struct {
	Client *ClientConfig `yaml:"client" json:"client" mapstructure:"client"`
	Server *ServerConfig `yaml:"server" json:"server" mapstructure:"server"`
}

type ClientConfig struct {
	Account             *AccountConfig `yaml:"account" json:"account" mapstructure:"account"`
	ConsistencyLevel    string         `yaml:"consistency" json:"consistency" mapstructure:"consistency"`
	DirectoryURL        string         `yaml:"directory" json:"directory" mapstructure:"directory"`
	Enrollment          *Enrollment    `yaml:"enrollment" json:"enrollment" mapstructure:"enrollment"`
	Subject             *ca.Subject    `yaml:"subject" json:"subject" mapstructure:"subject"`
	RequestServerBundle bool           `yaml:"request-server-bundle" json:"request_server_bundle" mapstructure:"request-server-bundle"`
}

type Enrollment struct {
	Challenge string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
	IPAddress string `yaml:"ip" json:"ip" mapstructure:"ip"`
}

type ServerConfig struct {
	DirectoryURL   string   `yaml:"directory" json:"directory" mapstructure:"directory"`
	Challenges     []string `yaml:"challenges" json:"challenges" mapstructure:"challenges"`
	TermsOfService string   `yaml:"terms-of-service" json:"terms_of_service" mapstructure:"terms-of-service"`
}

type AccountConfig struct {
	Email    string              `yaml:"email" json:"email" mapstructure:"email"`
	Key      *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	KeyID    string              `yaml:"kid" json:"kid" mapstructure:"kid"`
	Register bool                `yaml:"register" json:"register" mapstructure:"register"`
}

type CrossSign struct {
	DirectoryURL  string `yaml:"directory" json:"directory" mapstructure:"directory"`
	ChallengeType string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
}

type CertificateRequest struct {
	// CA common fields
	PermanentID   string                      `yaml:"permanent-id" json:"permanent_id" mapstructure:"permanent-id"`
	ProdModel     string                      `yaml:"prod-model" json:"prod_model" mapstructure:"prod-model"`
	ProdSerial    string                      `yaml:"prod-serial" json:"prod_serial" mapstructure:"prod-serial"`
	SANS          *ca.SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject       ca.Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid         int                         `yaml:"valid" json:"valid" mapstructure:"valid"`
	KeyAttributes *keystore.KeyAttributes     `yaml:"-" json:"-" mapstructure:"-"`
	// ACME specific fields
	AuthzID       *AuthzID   `yaml:"authz" json:"authz" mapstructure:"authz"`
	ChallengeType string     `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
	CrossSigner   *CrossSign `yaml:"cross-sign" json:"cross_sign" mapstructure:"cross-sign"`
	Renew         int        `yaml:"renew" json:"renew" mapstructure:"renew"`
}

type AuthzID struct {
	Type  *string `yaml:"type" json:"type" mapstructure:"type"`
	Value *string `yaml:"value" json:"value" mapstructure:"value"`
}
