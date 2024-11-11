package v1

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type Config struct {
	Certificate  Identity            `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	Home         string              `yaml:"home" json:"home" mapstructure:"home"`
	Index        string              `yaml:"index" json:"index" mapstructure:"index"`
	JWT          JWT                 `yaml:"jwt" json:"jwt" mapstructure:"jwt"`
	Key          *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Port         int                 `yaml:"port" json:"port" mapstructure:"port"`
	Proxy        *ProxyConfig        `yaml:"proxy" json:"proxy" mapstructure:"proxy"`
	RewriteRules []*RewriteRule      `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
	TLSPort      int                 `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	VirtualHosts *[]VirtualHost      `yaml:"virtual-hosts" json:"virtual_hosts" mapstructure:"virtual-hosts"`
	WebAuthn     *WebAuthn           `yaml:"webauthn" json:"webauthn" mapstructure:"webauthn"`
	CORS         *CORSConfig         `yaml:"cors" json:"cors" mapstructure:"cors"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed-origins" json:"allowed_origins" mapstructure:"allowed-origins"`
	AllowedMethods   []string `yaml:"allowed-methods" json:"allowed_methods" mapstructure:"allowed-methods"`
	AllowedHeaders   []string `yaml:"allowed-headers" json:"allowed_headers" mapstructure:"allowed-headers"`
	AllowCredentials bool     `yaml:"allow-credentials" json:"allow_credentials" mapstructure:"allow-credentials"`
}

type Identity struct {
	ACME    *acme.CertificateRequest    `yaml:"acme" json:"acme" mapstructure:"acme"`
	SANS    *ca.SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject ca.Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid   int                         `yaml:"valid" json:"valid" mapstructure:"valid"`
}

type JWT struct {
	Expiration int64  `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Issuer     string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
}

type ProxyConfig struct {
	Backends []string `yaml:"backends" json:"backends" mapstructure:"backends"`
}

type RewriteRule struct {
	Pattern string `yaml:"pattern" json:"pattern" mapstructure:"pattern"`
	Target  string `yaml:"target" json:"target" mapstructure:"target"`
}

type VirtualHost struct {
	Certificate  *Identity           `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	CORS         *CORSConfig         `yaml:"cors" json:"cors" mapstructure:"cors"`
	Home         string              `yaml:"home" json:"home" mapstructure:"home"`
	Hosts        []string            `yaml:"hosts" json:"hosts" mapstructure:"hosts"`
	Index        string              `yaml:"index" json:"index" mapstructure:"index"`
	Key          *keystore.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Proxy        *ProxyConfig        `yaml:"proxy" json:"proxy" mapstructure:"proxy"`
	RewriteRules []*RewriteRule      `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
}

type WebAuthn struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}
