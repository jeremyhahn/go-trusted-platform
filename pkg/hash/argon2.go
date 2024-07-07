package hash

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("argon2di: invalid format")
	ErrIncompatibleVersion = errors.New("argon2di: version incompatible")
)

type Argon2Params struct {
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

type Argon2Hasher struct {
	random io.Reader
	params Argon2Params
	Argon2
}

// Creates a new Argon2id password hasher using default parameters:
//
// Memory: 65536
// Iterations: 3
// Parallelism: 2
// SaltLength: 16
// KeyLength: 32
func NewArgon2(random io.Reader) Argon2 {
	return Argon2Hasher{
		random: random,
		params: Argon2Params{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32}}
}

// Creates a new Argon2id password hasher using default parameters
// using user-defined parameters.
func CreateArgon2(random io.Reader, params Argon2Params) Argon2 {
	return Argon2Hasher{random: random, params: params}
}

// Hashes the password using Argon2id
func (hasher Argon2Hasher) Hash(password string) (string, error) {
	salt, err := hasher.createSalt()
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt,
		hasher.params.Iterations,
		hasher.params.Memory,
		hasher.params.Parallelism,
		hasher.params.KeyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, hasher.params.Memory, hasher.params.Iterations,
		hasher.params.Parallelism, b64Salt, b64Hash)
	return encodedHash, nil
}

func (hasher Argon2Hasher) Compare(password,
	encodedHash string) (match bool, err error) {

	params, salt, hash, err := hasher.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt,
		params.Iterations, params.Memory, params.Parallelism,
		params.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

// Crates a random salt using the operating system runtime
func (hasher Argon2Hasher) createSalt() ([]byte, error) {
	// Use TPM random source and entropy configuration
	// to generate random salt
	b := make([]byte, hasher.params.SaltLength)
	n, err := hasher.random.Read(b)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("argon2: unexpected number of bytes from RNG")
	}
	return b, nil
}

// Decodes an Argon2id encoded hash
func (hasher Argon2Hasher) decodeHash(encodedHash string) (p Argon2Params,
	salt, hash []byte, err error) {

	var returnParams Argon2Params

	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return returnParams, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return returnParams, nil, nil, err
	}
	if version != argon2.Version {
		return returnParams, nil, nil, ErrIncompatibleVersion
	}

	p = Argon2Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory,
		&p.Iterations, &p.Parallelism)
	if err != nil {
		return returnParams, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return returnParams, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return returnParams, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
