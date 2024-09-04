package config

type Attestation struct {
	AllowAttestorSelfCA bool     `yaml:"allow-attestor-self-ca" json:"allow_attestor_self_ca" mapstructure:"allow-attestor-self-ca"`
	AllowOpenEnrollment bool     `yaml:"allow-open-enrollment" json:"allow-open-enrollment" mapstructure:"allow-open-enrollment"`
	AllowedVerifiers    []string `yaml:"allowed-verifiers" json:"allowed_verifiers" mapstructure:"allowed-verifiers"`
	ClientCACert        string   `yaml:"client-ca-cert" json:"client_ca_cert" mapstructure:"client-ca-cert"`
	InsecurePort        int      `yaml:"insecure-port" json:"insecure_port" mapstructure:"insecure-port"`
	InsecureSkipVerify  bool     `yaml:"insecure-skip-verify" json:"insecure_skip_verify" mapstructure:"insecure-skip-verify"`
	TLSPort             int      `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	QuotePCRs           []int32  `yaml:"quote-pcrs" json:"quote-pcrs" mapstructure:"quote-pcrs"`
}
