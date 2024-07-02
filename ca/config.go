package ca

type Config struct {
	Home                      string     `yaml:"home" json:"home" mapstructure:"home"`
	AutoImportIssuingCA       bool       `yaml:"auto-import-issuing-ca" json:"auto_import_issuing_ca" mapstructure:"auto-import-issuing-ca"`
	SystemCertPool            bool       `yaml:"system-cert-pool" json:"system_cert_pool" mapstructure:"system-cert-pool"`
	Identity                  []Identity `yaml:"identity" json:"identity" mapstructure:"identity"`
	ValidDays                 int        `yaml:"issued-valid-days" json:"issued-valid-days" mapstructure:"issued-valid-days"`
	IncludeLocalhostInSANS    bool       `yaml:"sans-include-localhost" json:"sans-include-localhost" mapstructure:"sans-include-localhost"`
	KeyAlgorithm              string     `yaml:"key-algorithm" json:"key-algorithm" mapstructure:"key-algorithm"`
	KeyStore                  string     `yaml:"key-store" json:"key-store" mapstructure:"key-store"`
	Hash                      string     `yaml:"hash" json:"hash" mapstructure:"hash"`
	RSAScheme                 string     `yaml:"rsa-scheme" json:"rsa-scheme" mapstructure:"rsa-scheme"`
	EllipticalCurve           string     `yaml:"elliptic-curve" json:"elliptic-curve" mapstructure:"elliptic-curve"`
	RequirePrivateKeyPassword bool       `yaml:"require-pkcs8-password" json:"require-pkcs8-password" mapstructure:"require-pkcs8-password"`
	PasswordPolicy            string     `yaml:"password-policy" json:"password-policy" mapstructure:"password-policy"`
	RetainRevokedCertificates bool       `yaml:"retain-revoked-certificates" json:"retain-revoked-certificates" mapstructure:"retain-revoked-certificates"`
	SignatureAlgorithm        string     `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
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
