package tpm2

import (
	"crypto/ecdh"
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
const (
	tpmPtManufacturer = 0x00000100 + 5  // PT_FIXED + offset of 5
	tpmPtVendorString = 0x00000100 + 6  // PT_FIXED + offset of 6
	tpmPtFwVersion1   = 0x00000100 + 11 // PT_FIXED + offset of 11

	ekIndex        = 0x81010001 //  TCG specified location for Endorsement Key.
	ekCertIndex    = 0x01C00002 //  TCG specified location for RSA-EK-certificate.
	ekECCCertIndex = 0x01C00002 //  TCG specified location for RSA-EK-certificate.
	srkIndex       = 0x81000001 //  TCG specified location for Storage Root Key
	idevIDKey      = 0x81020000
	idevIDCert     = 0x01C90000

	// Defined in "Registry of reserved TPM 2.0 handles and localities".
	nvramRSACertIndex    = 0x1c00002
	nvramRSAEkNonceIndex = 0x1c00003
	nvramECCCertIndex    = 0x1c0000a
	nvramECCEkNonceIndex = 0x1c0000b

	// Defined in "Registry of reserved TPM 2.0 handles and localities", and checked on a glinux machine.
	commonRSAEkEquivalentHandle = 0x81010001
	commonECCEkEquivalentHandle = 0x81010002
)

var (
	debugPCR = uint(16)

	// https://github.com/salrashid123/tpm2/blob/master/tpm2_direct_api/aes/main.go
	aesPrimaryTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	aesTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}
)

// type EK struct {
// 	// Public key of the EK.
// 	Public crypto.PublicKey

// 	// Certificate is the EK certificate for TPMs that provide it.
// 	Certificate *x509.Certificate

// 	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
// 	// Public key. Clients or servers can perform an HTTP GET to this URL, and
// 	// use ParseEKCertificate on the response body.
// 	CertificateURL string

// 	// The EK persistent handle.
// 	handle tpmutil.Handle
// }

type tpm20Info struct {
	vendor       string
	manufacturer TCGVendorID
	fwMajor      int
	fwMinor      int
}

type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

func (id TCGVendorID) String() string {
	return vendors[id]
}

// Defines the interface to the TPM Context store
type ContextStore interface {
	Get(key string) ([]byte, error)
	Save(key string, value []byte) error
}

type Key struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
	Public tpm2.TPMTPublic
	// BPublic        tpm2.TPM2BPublic
	BPublicBytes    []byte
	Auth            []byte
	RSAPubKey       *rsa.PublicKey
	PublicKeyBytes  []byte
	PublicKeyPEM    []byte
	RSAPrivKey      *rsa.PrivateKey
	PrivateKeyPEM   []byte
	PrivateKeyBytes []byte
	ECCPubKey       *ecdh.PublicKey
}

type DerivedKey struct {
	Key
	Name           []byte
	CreationHash   []byte
	CreationData   []byte
	CreationTicket []byte
}

type Credential struct {
	CredentialBlob  []byte
	EncryptedSecret []byte
}

type Quote struct {
	Quoted []byte
	Nonce  []byte
}
