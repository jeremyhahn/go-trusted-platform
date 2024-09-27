package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type FSExtension string
type Partition string
type KeyHalf uint8

const (
	DEFAULT_PASSWORD = "123456"

	// Key store file backend sub directories
	PARTITION_ROOT            Partition = ""
	PARTITION_TLS             Partition = "issued"
	PARTITION_ENCRYPTION_KEYS Partition = "encryption-keys"
	PARTITION_SIGNING_KEYS    Partition = "signing-keys"
	PARTITION_HMAC            Partition = "hmac-keys"
	PARTITION_SECRETS         Partition = "secrets"

	// Key store file extensions
	FSEXT_BLOB              FSExtension = ""
	FSEXT_PRIVATE_PKCS8     FSExtension = ".key"
	FSEXT_PRIVATE_PKCS8_PEM FSExtension = ".key.pem"
	FSEXT_PUBLIC_PKCS1      FSExtension = ".pub"
	FSEXT_PUBLIC_PEM        FSExtension = ".pub.pem"
	FSEXT_PRIVATE_BLOB      FSExtension = ".key.bin"
	FSEXT_PUBLIC_BLOB       FSExtension = ".pub.bin"
	FSEXT_DIGEST            FSExtension = ".digest"
	FSEXT_SIG               FSExtension = ".sig"

	// String literals using in platform configuration file
	STORE_PKCS8   StoreType = "pkcs8"
	STORE_PKCS11  StoreType = "pkcs11"
	STORE_TPM2    StoreType = "tpm2"
	STORE_UNKNOWN StoreType = "unknown"

	KEYHALF_PRIVATE KeyHalf = 1 + iota
	KEYHALF_PUBLIC

	// Internal types not stored in the platform configuration file
	KEY_TYPE_ATTESTATION KeyType = 1 + iota
	KEY_TYPE_CA
	KEY_TYPE_ENCRYPTION
	KEY_TYPE_ENDORSEMENT
	KEY_TYPE_HMAC
	KEY_TYPE_IDEVID
	KEY_TYPE_LDEVID
	KEY_TYPE_SECRET
	KEY_TYPE_SIGNING
	KEY_TYPE_STORAGE
	KEY_TYPE_TLS
	KEY_TYPE_TPM

	QUANTUM_ALGORITHM_DILITHIUM2 QuantumAlgorithm = 1 + iota

	ENCRYPT_ALGORITHM_RSA_PKCS1v15 = 1 + iota
	ENCRYPT_ALGORITHM_RSA_OAEP
	ENCRYPT_ALGORITHM_ECDH

	WRAP_RSA_OAEP_3072_SHA1_AES_256 WrapAlgorithm = 1 + iota
	WRAP_RSA_OAEP_4096_SHA1_AES_256
	WRAP_RSA_OAEP_3072_SHA256_AES_256
	WRAP_RSA_OAEP_4096_SHA256_AES_256
	WRAP_RSA_OAEP_3072_SHA256
	WRAP_RSA_OAEP_4096_SHA256
	WRAP_AES_GCM
)

var (
	ErrAlreadyInitialized        = errors.New("store/keystore: already initialized")
	ErrNotInitalized             = errors.New("store/keystore: not initialized")
	ErrInvalidKeyedHashSecret    = errors.New("store/keystore: invalid keyed hash secret")
	ErrInvalidKeyType            = errors.New("store/keystore: invalid key type")
	ErrInvalidKeyAlgorithm       = errors.New("store/keystore: invalid key algorithm")
	ErrInvalidParentAttributes   = errors.New("store/keystore: invalid parent key attributes")
	ErrInvalidPrivateKey         = errors.New("store/keystore: invalid private key")
	ErrInvalidPrivateKeyRSA      = errors.New("store/keystore: invalid RSA private key")
	ErrInvalidPrivateKeyECDSA    = errors.New("store/keystore: invalid ECDSA private key")
	ErrInvalidPrivateKeyEd25519  = errors.New("store/keystore: invalid Ed25519 private key")
	ErrInvalidOpaquePrivateKey   = errors.New("store/keystore: invalid opaque private key")
	ErrInvalidSignerOpts         = errors.New("store/keystore: invalid signer opts, password required")
	ErrInvalidKeyStore           = errors.New("store/keystore: invalid key store")
	ErrInvalidSignatureAlgorithm = errors.New("store/keystore: unsupported signing algorithm")
	ErrInvalidSignatureScheme    = errors.New("store/keystore: invalid signature scheme")
	ErrKeyAlreadyExists          = errors.New("store/keystore: key already exists")
	ErrFileIntegrityCheckFailed  = errors.New("store/keystore: file integrity check failed")
	ErrInvalidPublicKeyRSA       = errors.New("store/keystore: invalid RSA public key")
	ErrInvalidPublicKeyECDSA     = errors.New("store/keystore: invalid ECDSA public key")
	ErrSingatureVerification     = errors.New("store/keystore: signature verification failed")
	ErrInvalidCurve              = errors.New("store/keystore: invalid ECC curve")
	ErrInvalidHashFunction       = errors.New("store/keystore: invalid hash function")
	ErrInvalidKeyAttributes      = errors.New("store/keystore: invalid key attributes")
	ErrInvalidRSAAttributes      = errors.New("store/keystore: invalid RSA key attributes")
	ErrInvalidECCAttributes      = errors.New("store/keystore: invalid ECC key attributes")
	ErrInvalidBlobName           = errors.New("store/keystore: invalid blob name")
	ErrIssuerAttributeRequired   = errors.New("store/keystore: issuer common name attribute required")
	ErrSOPinRequired             = errors.New("store/keystore: security officer PIN required")
	ErrUserPinRequired           = errors.New("store/keystore: user PIN required")
	ErrInvalidPassword           = errors.New("store/keystore: invalid password")
	ErrInvalidKeyPartition       = errors.New("store/keystore: invalid key partition")
	ErrInvalidEncodingPEM        = errors.New("store/keystore: invalid PEM encoding")
	ErrUnsupportedKeyAlgorithm   = errors.New("store/keystore: unsupported key algorithm")
	ErrPasswordRequired          = errors.New("store/keystore: password required")
)

// The Key Store Module interface
type KeyStorer interface {
	Backend() KeyBackend
	Close() error
	Delete(attrs *KeyAttributes) error
	GenerateKey(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateRSA(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateECDSA(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateEd25519(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateSecretKey(attrs *KeyAttributes) error
	Decrypter(attrs *KeyAttributes) (crypto.Decrypter, error)
	Equal(opaque Opaque, x crypto.PrivateKey) bool
	Initialize(soPIN, userPIN Password) error
	Key(attrs *KeyAttributes) (OpaqueKey, error)
	Signer(attrs *KeyAttributes) (crypto.Signer, error)
	Type() StoreType
	Verifier(attrs *KeyAttributes, opts *VerifyOpts) Verifier
}

type TPMAttributes struct {
	BPublic              tpm2.TPM2BPublic
	CertHandle           tpm2.TPMHandle
	CertifyInfo          []byte
	CreationTicketDigest []byte
	Handle               tpm2.TPMHandle
	HandleType           tpm2.TPMHT
	HashAlg              tpm2.TPMIAlgHash
	Hierarchy            tpm2.TPMHandle
	HierarchyAuth        Password
	Name                 tpm2.TPM2BName
	PCRSelection         tpm2.TPMLPCRSelection
	PublicKeyBytes       []byte
	Public               tpm2.TPMTPublic
	PrivateKeyBlob       []byte
	SessionCloser        func() error
	Signature            []byte
	Template             tpm2.TPMTPublic
}

type StoreType string

func (st StoreType) String() string {
	return string(st)
}

type Verifier interface {
	Verify(
		pub crypto.PublicKey,
		hash crypto.Hash,
		hashed, signature []byte,
		opts *VerifyOpts) error
}

type VerifyOpts struct {
	KeyAttributes  *KeyAttributes
	BlobCN         []byte
	IntegrityCheck bool
	PSSOptions     *rsa.PSSOptions
}

type KeyAttributes struct {
	Debug              bool
	ECCAttributes      *ECCAttributes
	CN                 string
	Hash               crypto.Hash
	KeyAlgorithm       x509.PublicKeyAlgorithm
	KeyType            KeyType
	Parent             *KeyAttributes
	Password           Password
	PlatformPolicy     bool
	QuantumAlgorithm   *QuantumAlgorithm
	RSAAttributes      *RSAAttributes
	Secret             Password
	SignatureAlgorithm x509.SignatureAlgorithm
	StoreType          StoreType
	TPMAttributes      *TPMAttributes
	WrapAttributes     *KeyAttributes
}

type ECCAttributes struct {
	Curve elliptic.Curve
}

type RSAAttributes struct {
	KeySize int
}

type QuantumAlgorithm int

func (algo QuantumAlgorithm) String() string {
	return "Dilithium2"
}

type EncryptionAlgorithm uint8

func (algo EncryptionAlgorithm) String() string {
	switch algo {
	case ENCRYPT_ALGORITHM_RSA_PKCS1v15:
		return "RSA_PKCS1v15"
	case ENCRYPT_ALGORITHM_RSA_OAEP:
		return "RSA_OAEP"
	case ENCRYPT_ALGORITHM_ECDH:
		return "ECDH"
	}
	panic("store/keystore: invalid encryption algorithm")
}

type KeyType uint8

func (keyType KeyType) String() string {
	switch keyType {
	case KEY_TYPE_ATTESTATION:
		return "ATTESTATION"
	case KEY_TYPE_CA:
		return "CA"
	case KEY_TYPE_ENCRYPTION:
		return "ENCRYPTION"
	case KEY_TYPE_ENDORSEMENT:
		return "ENDORSEMENT"
	case KEY_TYPE_HMAC:
		return "HMAC"
	case KEY_TYPE_IDEVID:
		return "IDevID"
	case KEY_TYPE_LDEVID:
		return "LDevID"
	case KEY_TYPE_SECRET:
		return "SECRET"
	case KEY_TYPE_SIGNING:
		return "SIGNING"
	case KEY_TYPE_STORAGE:
		return "STORAGE"
	case KEY_TYPE_TLS:
		return "TLS"
	case KEY_TYPE_TPM:
		return "TPM"
	}
	panic("store/keystore: invalid key type attribute")
}

type WrapAlgorithm uint8

func (algo WrapAlgorithm) String() string {
	switch algo {
	case WRAP_RSA_OAEP_3072_SHA1_AES_256:
		return "WRAP_RSA_OAEP_3072_SHA1_AES_256"
	case WRAP_RSA_OAEP_4096_SHA1_AES_256:
		return "WRAP_RSA_OAEP_4096_SHA1_AES_256"
	case WRAP_RSA_OAEP_3072_SHA256_AES_256:
		return "WRAP_RSA_OAEP_3072_SHA256_AES_256"
	case WRAP_RSA_OAEP_4096_SHA256_AES_256:
		return "WRAP_RSA_OAEP_4096_SHA256_AES_256"
	case WRAP_RSA_OAEP_3072_SHA256:
		return "WRAP_RSA_OAEP_3072_SHA256"
	case WRAP_RSA_OAEP_4096_SHA256:
		return "WRAP_RSA_OAEP_4096_SHA256"
	case WRAP_AES_GCM:
		return "WRAP_AES_GCM"
	}
	panic("store/keystore: invalid key wrap algorithm")
}

func (attrs KeyAttributes) String() string {

	var sb strings.Builder

	var password, secret string

	if attrs.Debug {
		if attrs.Password != nil {
			var err error
			if attrs.Password != nil {
				password, err = attrs.Password.String()
				if err != nil {
					fmt.Println(err)
				}
			}
			if attrs.Secret != nil {
				secret, err = attrs.Secret.String()
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	}

	sb.WriteString("Key Attributes\n")
	sb.WriteString(fmt.Sprintf("  Common Name: %s\n", attrs.CN))
	sb.WriteString(fmt.Sprintf("  Debug: %t\n", attrs.Debug))
	sb.WriteString(fmt.Sprintf("  Hash: %s\n", attrs.Hash.String()))
	sb.WriteString(fmt.Sprintf("  Key Algorithm: %s\n", attrs.KeyAlgorithm))
	sb.WriteString(fmt.Sprintf("  Platform Policy: %t\n", attrs.PlatformPolicy))
	sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", attrs.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("  Store: %s\n", attrs.StoreType))
	sb.WriteString(fmt.Sprintf("  Type: %s\n", attrs.KeyType))

	if attrs.ECCAttributes != nil {
		sb.WriteString("ECC Attributes\n")
		sb.WriteString(fmt.Sprintf("  Curve: %+v\n", attrs.ECCAttributes.Curve.Params().Name))
	} else if attrs.RSAAttributes != nil {
		sb.WriteString("RSA Attributes\n")
		sb.WriteString(fmt.Sprintf("  Size: %d\n", attrs.RSAAttributes.KeySize))
	}

	if attrs.Debug {
		sb.WriteString("Secrets\n")
		sb.WriteString(fmt.Sprintf("  Password: %s\n", password))
		sb.WriteString(fmt.Sprintf("  Secret: %s\n", secret))
	}

	return sb.String()
}

func DebugKeyAttributes(logger *logging.Logger, attrs *KeyAttributes) {

	var password, secret string

	if attrs.Debug {
		if attrs.Password != nil {
			var err error
			if attrs.Password != nil {
				password, err = attrs.Password.String()
				if err != nil {
					logger.Error(err)
				}
			}
			if attrs.Secret != nil {
				secret, err = attrs.Secret.String()
				if err != nil {
					logger.Error(err)
				}
			}
		}
	}

	params := []any{
		slog.String("commonName", attrs.CN),
		slog.Bool("debug", attrs.Debug),
		slog.String("hash", attrs.Hash.String()),
		slog.String("algorithm", attrs.KeyAlgorithm.String()),
		slog.Bool("policy", attrs.PlatformPolicy),
		slog.String("signatureAlgorithm", attrs.SignatureAlgorithm.String()),
		slog.String("store", attrs.StoreType.String()),
		slog.String("type", attrs.KeyType.String()),
		slog.String("commonName", attrs.CN),
	}

	if attrs.ECCAttributes != nil {
		params = append(params, slog.String("curve", attrs.ECCAttributes.Curve.Params().Name))
	} else if attrs.RSAAttributes != nil {
		params = append(params, slog.Int("key-size", attrs.RSAAttributes.KeySize))
	}

	if attrs.Debug {
		params = append(params,
			slog.String("password", password),
			slog.String("secret", secret))
	}

	logger.Debug("Key Attributes", slog.Group("attributes", params...))

}

func PublicKeyToString(pub crypto.PublicKey) string {
	var sb strings.Builder
	sb.WriteString("Public Key:\n")
	switch pub.(type) {
	case *rsa.PublicKey:
		sb.WriteString(fmt.Sprintf("    Exponent: %d\n", pub.(*rsa.PublicKey).E))
		sb.WriteString(fmt.Sprintf("    Modulus: %d\n", pub.(*rsa.PublicKey).N))
	case *ecdsa.PublicKey:
		params := pub.(*ecdsa.PublicKey).Curve.Params()
		sb.WriteString(fmt.Sprintf("    Curve: %s\n", params.Name))
		sb.WriteString(fmt.Sprintf("    X: %d\n", pub.(*ecdsa.PublicKey).X))
		sb.WriteString(fmt.Sprintf("    Y: %d\n", pub.(*ecdsa.PublicKey).Y))
	case ed25519.PublicKey:
		sb.WriteString(fmt.Sprintf("    %s\n", hex.EncodeToString(pub.(ed25519.PublicKey))))
	}
	return sb.String()
}

// Creates a new digest using the specified hash function
func Digest(hash crypto.Hash, data []byte) ([]byte, error) {
	hasher := hash.New()
	hasher.Reset()
	n, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, common.ErrCorruptWrite
	}
	digest := hasher.Sum(nil)
	return digest[:], err
}

// Returns a map of crypto.Hash supported by the platform
func AvailableHashes() map[string]crypto.Hash {
	hashes := make(map[string]crypto.Hash, 19)
	hashes[crypto.MD4.String()] = crypto.MD4
	hashes[crypto.MD5.String()] = crypto.MD5
	hashes[crypto.SHA1.String()] = crypto.SHA1
	hashes[crypto.SHA224.String()] = crypto.SHA224
	hashes[crypto.SHA256.String()] = crypto.SHA256
	hashes[crypto.SHA384.String()] = crypto.SHA384
	hashes[crypto.SHA512.String()] = crypto.SHA512
	hashes[crypto.MD5SHA1.String()] = crypto.MD5SHA1
	hashes[crypto.RIPEMD160.String()] = crypto.RIPEMD160
	hashes[crypto.SHA3_224.String()] = crypto.SHA3_224
	hashes[crypto.SHA3_256.String()] = crypto.SHA3_256
	hashes[crypto.SHA3_384.String()] = crypto.SHA3_384
	hashes[crypto.SHA3_512.String()] = crypto.SHA3_512
	hashes[crypto.SHA512_224.String()] = crypto.SHA512_224
	hashes[crypto.SHA512_256.String()] = crypto.SHA512_256
	hashes[crypto.BLAKE2s_256.String()] = crypto.BLAKE2s_256
	hashes[crypto.BLAKE2b_256.String()] = crypto.BLAKE2b_256
	hashes[crypto.BLAKE2b_384.String()] = crypto.BLAKE2b_384
	hashes[crypto.BLAKE2b_512.String()] = crypto.BLAKE2b_512
	return hashes
}

func DebugAvailableHashes(logger *logging.Logger) {
	hashes := AvailableHashes()
	logger.Debug("Available Hash Functions")
	for _, v := range hashes {
		logger.Debugf("  %s", v)
	}
}

// Returns a map of available signature algorithms supported by the platform
func AvailableSignatureAlgorithms() map[string]x509.SignatureAlgorithm {
	algos := make(map[string]x509.SignatureAlgorithm, 10)
	algos[x509.SHA256WithRSA.String()] = x509.SHA256WithRSA
	algos[x509.SHA384WithRSA.String()] = x509.SHA384WithRSA
	algos[x509.SHA512WithRSA.String()] = x509.SHA512WithRSA
	algos[x509.ECDSAWithSHA256.String()] = x509.ECDSAWithSHA256
	algos[x509.ECDSAWithSHA384.String()] = x509.ECDSAWithSHA384
	algos[x509.ECDSAWithSHA512.String()] = x509.ECDSAWithSHA512
	algos[x509.SHA256WithRSAPSS.String()] = x509.SHA256WithRSAPSS
	algos[x509.SHA384WithRSAPSS.String()] = x509.SHA384WithRSAPSS
	algos[x509.SHA512WithRSAPSS.String()] = x509.SHA512WithRSAPSS
	algos[x509.PureEd25519.String()] = x509.PureEd25519
	return algos
}

func SignatureAlgorithmHashes() map[x509.SignatureAlgorithm]crypto.Hash {
	algos := make(map[x509.SignatureAlgorithm]crypto.Hash, 10)
	algos[x509.SHA256WithRSA] = crypto.SHA256
	algos[x509.SHA384WithRSA] = crypto.SHA384
	algos[x509.SHA512WithRSA] = crypto.SHA512
	algos[x509.ECDSAWithSHA256] = crypto.SHA256
	algos[x509.ECDSAWithSHA384] = crypto.SHA384
	algos[x509.ECDSAWithSHA512] = crypto.SHA512
	algos[x509.SHA256WithRSAPSS] = crypto.SHA256
	algos[x509.SHA384WithRSAPSS] = crypto.SHA384
	algos[x509.SHA512WithRSAPSS] = crypto.SHA512
	algos[x509.PureEd25519] = 0
	return algos
}

func DebugAvailableSignatureAkgorithms(logger *logging.Logger) {
	algos := AvailableSignatureAlgorithms()
	logger.Debug("Available Signature Algorithms")
	for _, v := range algos {
		logger.Debugf("  %s", v)
	}
}

// Returns a map of available key algorithms supported by the platform
func AvailableKeyAlgorithms() map[string]x509.PublicKeyAlgorithm {
	algos := make(map[string]x509.PublicKeyAlgorithm)
	algos[x509.RSA.String()] = x509.RSA
	algos[x509.ECDSA.String()] = x509.ECDSA
	algos[x509.Ed25519.String()] = x509.Ed25519
	return algos
}

func DebugAvailableKeyAkgorithms(logger *logging.Logger) {
	algos := AvailableKeyAlgorithms()
	logger.Debug("Available Key Algorithms")
	for _, v := range algos {
		logger.Debugf("  %s", v)
	}
}

// Converts crypto.Hash to platform file extension prefix
func FSHashName(hash crypto.Hash) string {
	name := strings.ToLower(hash.String())
	name = strings.ReplaceAll(name, "-", "")
	return strings.ReplaceAll(name, "/", "")
}

// Prefixes a key algorithm name to file extension
func KeyFileExtension(
	algo x509.PublicKeyAlgorithm,
	extension FSExtension,
	keyType *KeyType) FSExtension {

	keyExt := FSEXTKeyAlgorithm(algo)
	if keyType != nil && *keyType == KEY_TYPE_HMAC {
		if algo == x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash) {
			return FSExtension(fmt.Sprintf(".hmac%s", extension))
		} else {
			return FSExtension(fmt.Sprintf("%s.hmac%s", keyExt, extension))
		}
	}
	return FSExtension(fmt.Sprintf("%s%s", keyExt, extension))
}

// Converts an x509.PublicKeyAlgorithm to a platform file extension
func FSEXTKeyAlgorithm(algo x509.PublicKeyAlgorithm) string {
	return fmt.Sprintf(".%s", strings.ToLower(algo.String()))
}

// Converts keystore.KeyAttributes to a platform file extension
func FSKeyExtension(attrs KeyAttributes, ext FSExtension) string {
	return fmt.Sprintf("%s%s", FSEXTKeyAlgorithm(attrs.KeyAlgorithm), ext)
}

// Converts a hash function name to a file extension. Used to
// save a signed digest file with an appropriate file extension
// to the blob
func HashFileExtension(hash crypto.Hash) string {
	return fmt.Sprintf(".%s", FSHashName(hash))
}

// Returns true if the signature algorithm is one of RSA PSS
func IsRSAPSS(sigAlgo x509.SignatureAlgorithm) bool {
	return sigAlgo == x509.SHA256WithRSAPSS || sigAlgo == x509.SHA384WithRSAPSS ||
		sigAlgo == x509.SHA512WithRSAPSS
}

func IsECDSA(sigAlgo x509.SignatureAlgorithm) bool {
	return sigAlgo == x509.ECDSAWithSHA256 || sigAlgo == x509.ECDSAWithSHA384 ||
		sigAlgo == x509.ECDSAWithSHA512
}

func KeyAlgorithmFromSignatureAlgorithm(
	sigAlgo x509.SignatureAlgorithm) (x509.PublicKeyAlgorithm, error) {

	switch sigAlgo {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return x509.ECDSA, nil
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS,
		x509.SHA384WithRSA, x509.SHA384WithRSAPSS,
		x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return x509.RSA, nil
	case x509.PureEd25519:
		return x509.Ed25519, nil
	}
	return 0, ErrInvalidSignatureAlgorithm
}
