package config

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type WebService struct {
	Certificate   Identity            `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	Home          string              `yaml:"home" json:"home" mapstructure:"home"`
	JWTExpiration int                 `yaml:"jwt-expiration" json:"jwt_expiration" mapstructure:"jwt-expiration"`
	Key           *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Port          int                 `yaml:"port" json:"port" mapstructure:"port"`
	TLSPort       int                 `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
}

type Identity struct {
	SANS    *ca.SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject ca.Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid   int                         `yaml:"valid" json:"valid" mapstructure:"valid"`
}
