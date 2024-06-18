package config

import "github.com/jeremyhahn/go-trusted-platform/pki/ca"

type WebService struct {
	JWTExpiration int         `yaml:"jwt-expiration" json:"jwt_expiration" mapstructure:"jwt-expiration"`
	Port          int         `yaml:"port" json:"port" mapstructure:"port"`
	TLSPort       int         `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	TLSCA         string      `yaml:"tls-ca" json:"tls_ca" mapstructure:"tls-ca"`
	TLSKey        string      `yaml:"tls-key" json:"tls_key" mapstructure:"tls-key"`
	TLSCRT        string      `yaml:"tls-crt" json:"tls_crt" mapstructure:"tls-crt"`
	Certificate   ca.Identity `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
}
