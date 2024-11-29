package tpm2

import (
	"crypto"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

type EnrollmentStrategy string

// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
const (
	tpmPtManufacturer = 0x00000100 + 5  // PT_FIXED + offset of 5
	tpmPtVendorString = 0x00000100 + 6  // PT_FIXED + offset of 6
	tpmPtFwVersion1   = 0x00000100 + 11 // PT_FIXED + offset of 11

	// Defined in TCG TPM 2.0 Provisioning Guidance - Section 7.8 - NV Memory
	// Table 2: Reserved Handles for TPM Provisioning Fundamental Elements
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ekIndex         = 0x81010001
	ekCertIndex     = 0x01C00002
	srkIndexRSA2048 = 0x81000001
	srkIndexECCP256 = 0x81000002
	idevIDKey       = 0x81020000
	idevIDCert      = 0x01C90000

	// TCG TPM 2.0 Keys for Device Identity and Attestation
	// Section 7.3.2 - IDevID/IAK Policy NV Indices for Recoverable Keys
	// Section 7.3.3 - IDevID/IAK Unique String
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
	idevIDNVIndex = 0x01C90020

	ekCertIndexRSA2048 = 0x01C00002
	ekCertIndexECCP256 = 0x01C0000a
	ekCertIndexECCP384 = 0x01C00016
	ekCertIndexECCP521 = 0x01C00018

	// Defined in "Registry of reserved TPM 2.0 handles and localities".
	nvramRSACertIndex    = 0x1c00002
	nvramRSAEkNonceIndex = 0x1c00003
	nvramECCCertIndex    = 0x1c0000a
	nvramECCEkNonceIndex = 0x1c0000b

	nvramPlatformIndex    = 0x01400001
	nvramEndorsementIndex = 0x01C00001
	nvramOwnerIndex       = 0x01800001

	// Trusted Platform EK and SRK stored under the Platform Hierarchy
	// Registry of Reserved TPM 2.0 Handles and Localities, Section 2.3.1 - Key Handle Assignments
	tpEKIndex   = 0x81800001
	tpSRKIndex  = 0x81800002
	tpSealIndex = 0x81000002

	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
	infoOpeningSimulator  = "tpm: opening TPM simulator"
	infoOpeningDevice     = "tpm: opening TPM 2.0 device"
	infoClosingConnection = "tpm: closing TPM 2.0"

	EnrollmentStrategyIAK                    = EnrollmentStrategy("IAK")
	EnrollmentStrategyIAK_IDEVID_SINGLE_PASS = EnrollmentStrategy("IAK_IDEVID_SINGLE_PASS")

	binaryMeasurementsFileNameTemplate = "/sys/kernel/security/%s/binary_bios_measurements"
)

var (
	debugPCR = uint(16)

	tpm2SupportedPCRs = []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	tssWellKnownSecret = []byte{
		// TPM2_Clear(TSS_WELL_KNOWN_SECRET)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	ErrInvalidAKAttributes          = errors.New("tpm: invalid AK attributes")
	ErrInvalidEKCertFormat          = errors.New("tpm: invalid endorsement certificate format")
	ErrInvalidEKAttributes          = errors.New("tpm: invalid EK attributes")
	ErrInvalidEKCert                = errors.New("tpm: failed to verify endorsement key certificate")
	ErrDeviceAlreadyOpen            = errors.New("tpm: device already open")
	ErrOpeningDevice                = errors.New("tpm: error opening device")
	ErrInvalidSessionType           = errors.New("tpm: invalid session type")
	ErrInvalidSRKAuth               = errors.New("tpm: invalid storage root key auth")
	ErrInvalidActivationCredential  = errors.New("tpm: invalid activation credential")
	ErrHashAlgorithmNotSupported    = errors.New("tpm: hash algorithm not supported")
	ErrInvalidPolicyDigest          = errors.New("tpm: invalid policy digest")
	ErrInvalidHandle                = errors.New("tpm: invalid entity handle")
	ErrUnexpectedRandomBytes        = errors.New("tpm: unexpected number of random bytes read")
	ErrInvalidPCRIndex              = errors.New("tpm: invalid PCR index")
	ErrInvalidNonce                 = errors.New("tpm: invalid nonce")
	ErrNotInitialized               = errors.New("tpm: not initialized")
	ErrEndorsementCertNotFound      = errors.New("tpm: endorsement certificate not found")
	ErrInvalidKeyStoreConfiguration = errors.New("tpm: invalid key store configuration")
	ErrInvalidHashFunction          = errors.New("tpm: invalid hash function")
	ErrInvalidSessionAuthorization  = errors.New("tpm: invalid session authorization")
	ErrMissingMeasurementLog        = errors.New("tpm: binary measurement log not found")
	ErrRSAPSSNotSupported           = errors.New("tpm: RSA-PSS / FIPS 140-2 not supported by this TPM")
	ErrInvalidEnrollmentStrategy    = errors.New("tpm: invalid enrollment strategy")

	// TPM_RC errors
	ErrCommandNotSupported = tpm2.TPMRC(0xb0143)

	warnMissingLocalAttestationPCRs = errors.New("tpm: Local attestation PCRs missing from configuration file")

	// RSA SSA Template
	RSASSATemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// RSA PSS Template
	RSAPSSTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// ECC P256 Template
	ECCP256Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	// Attestation Key
	// See TPM 2.0 Keys for Device Identity and Attestation
	// Section 4.1: Verifying TPM Protection of an Attestation Key
	// An AK MUST have the following characteristics:
	// - Restricted
	// - Signing
	// - Not-decrypting
	// - FixedTPM

	// RSA SSA AK Template (restricted signing, not decrypting, fixedtpm)
	RSASSAAKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// RSA PSS AK Template (restricted signing, not decrypting, fixedtpm)
	RSAPSSAKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// ECC P256 AK Template (restricted signing, not decrypting, fixedtpm)
	ECCAKP256Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	// IDevID Key
	// See TPM 2.0 Keys for Device Identity and Attestation
	// Section 4.1: Verifying TPM Protection of a DevID Key
	// A DevID MUST have the following characteristics:
	// - Not-Restricted
	// - Signing
	// - Not-decrypting
	// - FixedTPM

	// RSA SSA IDevID Template (non-restricted signing, not decrypting, fixedtpm)
	RSASSAIDevIDTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// RSA PSS IDevID Template (non-restricted signing, not decrypting, fixedtpm)
	RSAPSSIDevIDTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
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

	// ECC P256 IDevID Template (non-restricted signing, not decrypting, fixedtpm)
	ECCIDevIDP256Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	// AES Templates

	AES128CFBTemplate = tpm2.TPMTPublic{
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

	AES256CFBTemplate = tpm2.TPMTPublic{
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
						tpm2.TPMKeyBits(256),
					),
				},
			},
		),
	}

	// Keyed hash / HMAC Template
	KeyedHashTemplate = tpm2.TPMTPublic{
		Type:       tpm2.TPMAlgKeyedHash,
		NameAlg:    tpm2.TPMAlgSHA256,
		AuthPolicy: tpm2.TPM2BDigest{},
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
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

// TPM 2.0 Keys for Device Identity and Attestation -
// Section 13.1 - TCG-CSR-IDEVID
type TCG_CSR_IDEVID struct {
	StructVer   [4]byte
	Contents    [4]byte
	SigSz       [4]byte
	CsrContents TCG_IDEVID_CONTENT
	Signature   []byte
}

type TCG_IDEVID_CONTENT struct {
	StructVer                 [4]byte
	HashAlgoId                [4]byte
	HashSz                    [4]byte
	ProdModelSz               [4]byte
	ProdSerialSz              [4]byte
	ProdCaDataSz              [4]byte
	BootEvntLogSz             [4]byte
	EkCertSZ                  [4]byte
	AttestPubSZ               [4]byte
	AtCreateTktSZ             [4]byte
	AtCertifyInfoSZ           [4]byte
	AtCertifyInfoSignatureSZ  [4]byte
	SigningPubSZ              [4]byte
	SgnCertifyInfoSZ          [4]byte
	SgnCertifyInfoSignatureSZ [4]byte
	PadSz                     [4]byte
	ProdModel                 []byte
	ProdSerial                []byte
	ProdCaData                []byte
	BootEvntLog               []byte
	EkCert                    []byte
	AttestPub                 []byte
	AtCreateTkt               []byte
	AtCertifyInfo             []byte
	AtCertifyInfoSig          []byte
	SigningPub                []byte
	SgnCertifyInfo            []byte
	SgnCertifyInfoSig         []byte
	Pad                       []byte
}

// Represents an unpacked TCG-CSR-IDEVID. All binary
// fields are unmarshalled to their native Golang types,
// including size fields which the TCG spec requires
// encoded as 4 bytes big endian.
// // https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
type UNPACKED_TCG_CSR_IDEVID struct {
	StructVer   uint32
	Contents    uint32
	SigSz       uint32
	CsrContents UNPACKED_TCG_IDEVID_CONTENT
	RawBytes    []byte
	Signature   []byte
}

type UNPACKED_TCG_IDEVID_CONTENT struct {
	StructVer                 uint32
	HashAlgoId                uint32
	HashSz                    uint32
	ProdModelSz               uint32
	ProdSerialSz              uint32
	ProdCaDataSz              uint32
	BootEvntLogSz             uint32
	EkCertSZ                  uint32
	AttestPubSZ               uint32
	AtCreateTktSZ             uint32
	AtCertifyInfoSZ           uint32
	AtCertifyInfoSignatureSZ  uint32
	SigningPubSZ              uint32
	SgnCertifyInfoSZ          uint32
	SgnCertifyInfoSignatureSZ uint32
	PadSz                     uint32
	ProdModel                 []byte
	ProdSerial                []byte
	ProdCaData                []byte
	BootEvntLog               []byte
	EkCert                    []byte
	AttestPub                 []byte
	AtCreateTkt               []byte
	AtCertifyInfo             []byte
	AtCertifyInfoSig          []byte
	SigningPub                []byte
	SgnCertifyInfo            []byte
	SgnCertifyInfoSig         []byte
	Pad                       []byte
}

// Represents an unpacked TCG-CSR-LDEVID. All binary
// fields are unmarshalled to their native Golang types,
// including size fields which the TCG spec requires
// encoded as 4 bytes big endian.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
type UNPACKED_TCG_CSR_LDEVID struct {
	StructVer   uint32
	Contents    uint32
	SigSz       uint32
	CsrContents UNPACKED_TCG_IDEVID_CONTENT
	Signature   []byte
}

type UNPACKED_TCG_LDEVID_CONTENT struct {
	StructVer                uint32
	HashAlgoId               uint32
	HashSz                   uint32
	EkCertSZ                 uint32
	IakCertSZ                uint32
	PlatCertSZ               uint32
	PubkeySZ                 uint32
	AtCertifyInfoSZ          uint32
	AtCertifyInfoSignatureSZ uint32
	PadSz                    uint32
	EkCert                   []byte
	IakCert                  []byte
	PlatCert                 []byte
	Pubkey                   []byte
	AtCertifyInfo            []byte
	AtCertifyInfoSig         []byte
}

type TCG_CSR_LDEVID struct {
	StructVer   [4]byte
	Contents    [4]byte
	SigSz       [4]byte
	CsrContents TCG_LDEVID_CONTENT
	Signature   []byte
}

type TCG_LDEVID_CONTENT struct {
	StructVer                [4]byte
	HashAlgoId               [4]byte
	HashSz                   [4]byte
	EkCertSZ                 [4]byte
	IakCertSZ                [4]byte
	PlatCertSZ               [4]byte
	PubkeySZ                 [4]byte
	AtCertifyInfoSZ          [4]byte
	AtCertifyInfoSignatureSZ [4]byte
	PadSz                    [4]byte
	EkCert                   []byte
	IakCert                  []byte
	PlatCert                 []byte
	Pubkey                   []byte
	AtCertifyInfo            []byte
	AtCertifyInfoSig         []byte
}

type AKProfile struct {
	EKPub              []byte
	AKPub              []byte
	AKName             tpm2.TPM2BName
	SignatureAlgorithm x509.SignatureAlgorithm
}

type Quote struct {
	Quoted    []byte
	Signature []byte
	Nonce     []byte
	PCRs      []byte
	EventLog  []byte
}

type PCRBank struct {
	Algorithm string
	PCRs      []PCR
}

type PCR struct {
	ID    int32
	Value []byte
}

func HierarchyName(hierarchy tpm2.TPMHandle) string {
	switch hierarchy {

	case tpm2.TPMRHPlatform:
		return "PLATFORM"

	case tpm2.TPMRHOwner:
		return "OWNER"

	case tpm2.TPMRHEndorsement:
		return "ENDORSEMENT"

	case tpm2.TPMRHNull:
		return "NULL"
	}

	panic("tpm: invalid hierarchy")
}

func ParseHashAlgFromString(hash string) (tpm2.TPMIAlgHash, error) {
	switch strings.ToUpper(hash) {
	case crypto.SHA256.String():
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384.String():
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512.String():
		return tpm2.TPMAlgSHA512, nil
	}
	return 0, ErrInvalidHashFunction
}

func ParseHashAlg(hash crypto.Hash) (tpm2.TPMIAlgHash, error) {
	switch hash {
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	}
	return 0, ErrInvalidHashFunction
}

func ParseHashSize(hash crypto.Hash) (uint32, error) {
	switch hash {
	case crypto.SHA256:
		return 32, nil
	case crypto.SHA384:
		return 48, nil
	case crypto.SHA512:
		return 64, nil
	}
	return 0, ErrInvalidHashFunction
}
