package argon2

type Argon2Config struct {
	Memory      uint32 `yaml:"memory" json:"memory" mapstructure:"memory"`
	Iterations  uint32 `yaml:"iterations" json:"iterations" mapstructure:"iterations"`
	Parallelism uint8  `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`
	SaltLength  uint32 `yaml:"saltLen" json:"saltLen" mapstructure:"saltLen"`
	KeyLength   uint32 `yaml:"keyLen" json:"keyLen" mapstructure:"keyLen"`
}

type Argon2 interface {
	Hash(password string) (string, error)
	Compare(password, hash string) (match bool, err error)
}
