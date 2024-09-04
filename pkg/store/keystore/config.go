package keystore

type KeyConfig struct {
	Debug              bool       `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	CN                 string     `yaml:"cn" json:"cn" mapstructure:"cn"`
	Default            bool       `yaml:"default" json:"default" mapstructure:"default"`
	Hash               string     `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string     `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Parent             *KeyConfig `yaml:"parent" json:"parent" mapstructure:"parent"`
	Password           string     `yaml:"password" json:"password" mapstructure:"password"`
	RSAConfig          *RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	PlatformPolicy     bool       `yaml:"platform-policy" json:"platform-policy" mapstructure:"platform-policy"`
	Secret             string     `yaml:"secret" json:"secret" mapstructure:"secret"`
	SignatureAlgorithm string     `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
	StoreType          string     `yaml:"store" json:"store" mapstructure:"store"`
}

type ECCConfig struct {
	Curve string `yaml:"curve" json:"curve" mapstructure:"curve"`
}

type RSAConfig struct {
	KeySize int `yaml:"size" json:"size" mapstructure:"size"`
}

// Parses the provided KeyConfig and returns KeyAttributes
func KeyAttributesFromConfig(config *KeyConfig) (*KeyAttributes, error) {

	algorithm, err := ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	hash, err := ParseHash(config.Hash)
	if err != nil {
		return nil, err
	}

	sigAlgo, err := ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	storeType, err := ParseStoreType(config.StoreType)
	if err != nil {
		return nil, err
	}

	attrs := &KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            KEY_TYPE_CA,
		Password:           NewClearPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		Secret:             NewClearPassword([]byte(config.Secret)),
		SignatureAlgorithm: sigAlgo,
		StoreType:          storeType,
	}

	if config.ECCConfig != nil {
		curve, err := ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	if config.Parent != nil {
		parent, err := KeyAttributesFromConfig(config.Parent)
		if err != nil {
			return nil, err
		}
		attrs.Parent = parent
	}

	return attrs, nil
}
