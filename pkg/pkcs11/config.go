package pkcs11

type Config struct {
	Library       string `yaml:"library" json:"library" mapstructure:"library"`
	LibraryConfig string `yaml:"config" json:"config" mapstructure:"config"`
	Slot          int    `yaml:"slot" json:"slot" mapstructure:"slot"`
	SOPin         int    `yaml:"so-pin" json:"so_pin" mapstructure:"so-pin"`
	Pin           string `yaml:"pin" json:"pin" mapstructure:"pin"`
	TokenLabel    string `yaml:"label" json:"label" mapstructure:"label"`
}
