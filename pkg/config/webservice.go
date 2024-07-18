package config

import "github.com/jeremyhahn/go-trusted-platform/pkg/ca"

type WebService struct {
	JWTExpiration   int         `yaml:"jwt-expiration" json:"jwt_expiration" mapstructure:"jwt-expiration"`
	Port            int         `yaml:"port" json:"port" mapstructure:"port"`
	TLSPort         int         `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	TLSCA           string      `yaml:"tls-ca" json:"tls_ca" mapstructure:"tls-ca"`
	TLSCRT          string      `yaml:"tls-crt" json:"tls_crt" mapstructure:"tls-crt"`
	TLSKey          string      `yaml:"tls-key" json:"tls_key" mapstructure:"tls-key"`
	TLSKeyAlgorithm string      `yaml:"tls-key-algorithm" json:"tls_key_algorithm" mapstructure:"tls-key-algorithm"`
	Certificate     ca.Identity `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
}
