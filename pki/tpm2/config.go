package tpm2

type Config struct {
	EKCertIndex    uint32 `yaml:"ek-cert-index" json:"ek-cert-index" mapstructure:"ex-cert-index"`
	Device         string `yaml:"device" json:"device" mapstructure:"device"`
	EKCert         string `yaml:"ek-cert" json:"ek_cert" mapstructure:"ek-cert"`
	EncryptSession bool   `yaml:"encrypt-sessions" json:"encrypt_sessions" mapstructure:"encrypt-sessions"`
	UseEntropy     bool   `yaml:"entropy" json:"entropy" mapstructure:"entropyr"`
}
