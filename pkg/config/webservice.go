package config

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type WebService struct {
	Certificate Identity            `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	Home        string              `yaml:"home" json:"home" mapstructure:"home"`
	JWT         JWT                 `yaml:"jwt" json:"jwt" mapstructure:"jwt"`
	Key         *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Port        int                 `yaml:"port" json:"port" mapstructure:"port"`
	TLSPort     int                 `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	WebAuthn    *WebAuthn           `yaml:"webauthn" json:"webauthn" mapstructure:"webauthn"`
}

type Identity struct {
	SANS    *ca.SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject ca.Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid   int                         `yaml:"valid" json:"valid" mapstructure:"valid"`
}

type JWT struct {
	Expiration int64  `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Issuer     string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
}

type WebAuthn struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}
