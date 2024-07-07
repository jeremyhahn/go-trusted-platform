package pkcs11

type Config struct {
	Library    string `yaml:"library" json:"library" mapstructure:"library"`
	ConfigFile string `yaml:"config" json:"config" mapstructure:"config"`
}
