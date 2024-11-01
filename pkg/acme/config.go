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
	Account          *AccountConfig `yaml:"account" json:"account" mapstructure:"account"`
	ConsistencyLevel string         `yaml:"consistency" json:"consistency" mapstructure:"consistency"`
	DirectoryURL     string         `yaml:"directory" json:"directory" mapstructure:"directory"`
	Subject          *ca.Subject    `yaml:"subject" json:"subject" mapstructure:"subject"`
	Orders           *OrderConfig   `yaml:"orders" json:"orders" mapstructure:"orders"`
}

type AccountConfig struct {
	Email string              `yaml:"email" json:"email" mapstructure:"email"`
	Key   *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	KeyID string              `yaml:"kid" json:"kid" mapstructure:"kid"`
}

type OrderConfig struct {
	AutoRenew         bool   `yaml:"auto-renew" json:"auto-renew" mapstructure:"auto-renew"`
	AttestationFormat string `yaml:"attestation-format" json:"attestation_format" mapstructure:"attestation-format"`
	Challenge         string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
	Renewal           string `yaml:"renewal" json:"renewal" mapstructure:"renewal"`
}

// type EnrollmentConfig struct {
// 	Challenge   string             `yaml:"challenge" json:"challenge" mapstructure:"challenge"`
// 	Attestation *AttestationConfig `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
// }

// type AttestationConfig struct {
// 	KeyID  string `yaml:"key-id" json:"key_id" mapstructure:"key-id"`
// 	Format string `yaml:"format" json:"format" mapstructure:"format"`
// }

type ServerConfig struct {
}
