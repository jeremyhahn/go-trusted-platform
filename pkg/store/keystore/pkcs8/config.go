package pkcs8

type Config struct {
	CN             string `yaml:"cn" json:"cn" mapstructure:"cn"`
	PlatformPolicy bool   `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}
