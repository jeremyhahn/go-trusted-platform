package ca

type Config struct {
	AutoImportIssuingCA    bool       `yaml:"auto-import-issuing-ca" json:"auto_import_issuing_ca" mapstructure:"auto-import-issuing-ca"`
	SystemCertPool         bool       `yaml:"system-cert-pool" json:"system_cert_pool" mapstructure:"system-cert-pool"`
	Identity               []Identity `yaml:"identity" json:"identity" mapstructure:"identity"`
	ValidDays              int        `yaml:"issued-valid-days" json:"issued-valid-days" mapstructure:"issued-valid-days"`
	IncludeLocalhostInSANS bool       `yaml:"sans-include-localhost" json:"sans-include-localhost" mapstructure:"sans-include-localhost"`
}

type Identity struct {
	KeySize int                      `yaml:"key-size" json:"key_size" mapstructure:"key-size"`
	Valid   int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
	Subject Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	SANS    *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
}

type Subject struct {
	CommonName         string `yaml:"cn" json:"cn" mapstructure:"cn"`
	Organization       string `yaml:"organization" json:"organization" mapstructure:"organization"`
	OrganizationalUnit string `yaml:"organizational-unit" json:"organizational_unit" mapstructure:"organizational-unit"`
	Country            string `yaml:"country" json:"country" mapstructure:"country"`
	Province           string `yaml:"province" json:"province" mapstructure:"province"`
	Locality           string `yaml:"locality" json:"locality" mapstructure:"locality"`
	Address            string `yaml:"address" json:"address" mapstructure:"address"`
	PostalCode         string `yaml:"postal-code" json:"postal_code" mapstructure:"postal-code"`
}

type SubjectAlternativeNames struct {
	DNS   []string `yaml:"dns" json:"dns" mapstructure:"dns"`
	IPs   []string `yaml:"ips" json:"ips" mapstructure:"ips"`
	Email []string `yaml:"email" json:"email" mapstructure:"email"`
}
