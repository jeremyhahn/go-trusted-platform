package config

type Attestation struct {
	Service             string   `yaml:"service" json:"service" mapstructure:"service"`
	ServiceCACert       string   `yaml:"service-ca-cert" json:"service_ca_cert" mapstructure:"service-ca-cert"`
	TLSPort             int      `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	InsecurePort        int      `yaml:"insecure-port" json:"insecure_port" mapstructure:"insecure-port"`
	ClientCACert        string   `yaml:"client-ca-cert" json:"client_ca_cert" mapstructure:"client-ca-cert"`
	InsecureSkipVerify  bool     `yaml:"insecure-skip-verify" json:"insecure_skip_verify" mapstructure:"insecure-skip-verify"`
	AllowedVerifiers    []string `yaml:"allowed-verifiers" json:"allowed_verifiers" mapstructure:"allowed-verifiers"`
	AllowAttestorSelfCA bool     `yaml:"allow-attestor-self-ca" json:"allow_attestor_self_ca" mapstructure:"allow-attestor-self-ca"`
	EkCertForm          string   `yaml:"ek-cert-form" json:"ek_cert_form" mapstructure:"ek-cert-form"`
	AllowOpenEnrollment bool     `yaml:"allow-open-enrollment" json:"allow-open-enrollment" mapstructure:"allow-open-enrollment"`
	QuotePCRs           []int32  `yaml:"quote-pcrs" json:"quote-pcrs" mapstructure:"quote-pcrs"`
}
