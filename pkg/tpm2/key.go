package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Returns the Endorsement Public Key
func (tpm *TPM2) EK() crypto.PublicKey {
	if tpm.ekAttrs == nil {
		panic(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.ekAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		panic(ErrNotInitialized)
	}
	return pub
}

// Returns the Endorsement Key name and public area. Errors
// are fatal.
func (tpm *TPM2) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic) {
	ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
	name, pub, err := tpm.ReadHandle(ekHandle)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	return name, pub
}

// Returns the Endorsement Public RSA Key. Errors
// are fatal.
func (tpm *TPM2) EKRSA() *rsa.PublicKey {
	if tpm.ekRSAPubKey == nil {
		_, ekPub := tpm.EKPublic()
		rsaDetail, err := ekPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Fatal(err)
		}
		rsaUnique, err := ekPub.Unique.RSA()
		if err != nil {
			tpm.logger.Fatal(err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			tpm.logger.Fatal(err)
		}
		tpm.ekRSAPubKey = rsaPub
	}
	return tpm.ekRSAPubKey
}

// Returns the Endorsement Public ECC Key. Errors
// are fatal.
func (tpm *TPM2) EKECC() *ecdsa.PublicKey {
	if tpm.ekECCPubKey == nil {
		_, ekPub := tpm.EKPublic()
		ecDetail, err := ekPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Fatal(err)
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.Fatal(err)
		}
		eccUnique, err := ekPub.Unique.ECC()
		if err != nil {
			tpm.logger.Fatal(err)
		}
		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		tpm.ekECCPubKey = eccPub
	}
	return tpm.ekECCPubKey
}

// Returns the Shared Storage Root Key name and public area.
// Errors are fatal.
func (tpm *TPM2) SSRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic) {
	srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
	name, pub, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	return name, pub
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IAKAttributes() (*keystore.KeyAttributes, error) {
	if tpm.iakAttrs == nil {
		iakHandle := tpm2.TPMHandle(tpm.config.IAK.Handle)
		iakAttrs, err := tpm.TPMAttributes(iakHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.IAK.CN == "" {
			iakAttrs.CN = "default-device-id"
		}
		iakAttrs.KeyType = keystore.KEY_TYPE_ATTESTATION
		iakAttrs.StoreType = keystore.STORE_TPM2
		if err != nil {
			return nil, err
		}
		tpm.iakAttrs = iakAttrs
	}
	return tpm.iakAttrs, nil
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IAK() crypto.PublicKey {
	if tpm.iakAttrs == nil {
		panic(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.iakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	return pub
}

// Returns the Initial Device IDentifier Key Attributes
func (tpm *TPM2) IDevIDAttributes() (*keystore.KeyAttributes, error) {
	if tpm.idevidAttrs == nil {
		idevidHandle := tpm2.TPMHandle(tpm.config.IDevID.Handle)
		idevidAttrs, err := tpm.TPMAttributes(idevidHandle)
		if err != nil {
			return nil, err
		}
		tpm.idevidAttrs = idevidAttrs
	}
	return tpm.idevidAttrs, nil
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IDevID() crypto.PublicKey {
	if tpm.idevidAttrs == nil {
		tpm.logger.Fatal(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.iakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	return pub
}

// Returns the Endorsement Key atrributes using the handle defined
// in the platform configuration file.
func (tpm *TPM2) EKAttributes() (*keystore.KeyAttributes, error) {
	if tpm.ekAttrs == nil {
		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		ekAttrs, err := tpm.TPMAttributes(ekHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.EK.CN == "" {
			ekAttrs.CN = "ek"
		}
		ekAttrs.KeyType = keystore.KEY_TYPE_ENDORSEMENT
		ekAttrs.StoreType = keystore.STORE_TPM2

		algo, err := keystore.ParseKeyAlgorithm(tpm.config.EK.KeyAlgorithm)
		if err != nil {
			return nil, err
		}
		ekAttrs.KeyAlgorithm = algo

		if algo == x509.RSA {
			ekAttrs.RSAAttributes = &keystore.RSAAttributes{
				KeySize: tpm.config.EK.RSAConfig.KeySize,
			}
		} else {
			curve, err := keystore.ParseCurve(tpm.config.EK.ECCConfig.Curve)
			if err != nil {
				return nil, err
			}
			ekAttrs.ECCAttributes = &keystore.ECCAttributes{
				Curve: curve,
			}
		}
		tpm.ekAttrs = ekAttrs
	}
	return tpm.ekAttrs, nil
}

// Returns the Shared Storage Root Key under the Owner hierarchy
// using it's persistent handle.
func (tpm *TPM2) SSRKAttributes() (*keystore.KeyAttributes, error) {
	if tpm.ssrkAttrs == nil {
		srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
		srkAttrs, err := tpm.TPMAttributes(srkHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.SSRK.CN == "" {
			srkAttrs.CN = "shared-srk"
		}
		srkAttrs.KeyType = keystore.KEY_TYPE_STORAGE
		srkAttrs.StoreType = keystore.STORE_TPM2
		if err != nil {
			return nil, err
		}
		tpm.ssrkAttrs = srkAttrs
	}
	return tpm.ssrkAttrs, nil
}

// Reads the public area of the provided persistent TPM handle
// and returns a default set of KeyAttributes with the name,
// public area and algorithm set.
func (tpm *TPM2) TPMAttributes(
	handle tpm2.TPMHandle) (*keystore.KeyAttributes, error) {

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	keyPub, err := pub.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	keyAlgo := x509.RSA
	if keyPub.Type == tpm2.TPMAlgECC {
		keyAlgo = x509.ECDSA
	}

	pubKey, err := tpm.ParsePublicKey(pub.OutPublic.Bytes())
	if err != nil {
		return nil, err
	}

	publicDER, err := keystore.EncodePubKey(pubKey)
	if err != nil {
		return nil, err
	}

	attrs := &keystore.KeyAttributes{
		Debug:        tpm.debugSecrets,
		KeyAlgorithm: keyAlgo,
		KeyType:      keystore.KEY_TYPE_TPM,
		StoreType:    keystore.STORE_TPM2,
		Hash:         tpm.hash,
		TPMAttributes: &keystore.TPMAttributes{
			BPublic:        pub.OutPublic,
			Handle:         handle,
			HandleType:     tpm2.TPMHTPersistent,
			HashAlg:        tpm2.TPMAlgSHA256,
			Hierarchy:      tpm2.TPMRHOwner,
			Name:           pub.Name,
			Public:         *keyPub,
			PublicKeyBytes: publicDER,
		},
	}

	if keyPub.Type == tpm2.TPMAlgRSA {
		attrs.KeyAlgorithm = x509.RSA
	} else if keyPub.Type == tpm2.TPMAlgECC {
		attrs.KeyAlgorithm = x509.ECDSA
	} else {
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	return attrs, nil
}

// Creates a TCG compliant persistent Endorsement Key under the Endorsement
// Hierarchy. Optionally encrypts bus communication between the CPU <-> TPM
// if enabled in the platform configuration file.
func (tpm *TPM2) CreateEK(
	keyAttrs *keystore.KeyAttributes) error {

	var err error

	tpmAttrs := keyAttrs.TPMAttributes
	hierarchy := tpm2.TPMHandle(tpmAttrs.Hierarchy)

	var hierarchyAuth, userAuth []byte
	if tpmAttrs.HierarchyAuth != nil {
		hierarchyAuth, err = tpmAttrs.HierarchyAuth.Bytes()
		if err != nil {
			return err
		}
	}

	if keyAttrs.Password != nil {
		userAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return err
		}
	}

	if keyAttrs.PlatformPolicy {
		tpmAttrs.Template.AuthPolicy = tpm.policyDigest
	}

	// Create new EK primary key under the Endorsement Hierarchy
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(tpmAttrs.Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: userAuth,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: Created %s EK: 0x%x",
		keyAttrs.KeyAlgorithm.String(), primaryKey.ObjectHandle)

	ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)

	// Make the EK persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(ekHandle),
	}.Execute(tpm.transport)
	defer tpm.Flush(primaryKey.ObjectHandle)

	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: EK persisted to 0x%x", tpmAttrs.Handle)

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: EK Hierarchy: %s", HierarchyName(hierarchy))
	tpm.logger.Debugf("tpm: EK Name: 0x%x", Encode(primaryKey.Name.Buffer))

	keyAttrs.KeyType = keystore.KEY_TYPE_ENDORSEMENT
	tpmAttrs.Handle = ekHandle
	tpmAttrs.Name = primaryKey.Name
	tpmAttrs.Public = *pub

	return nil
}

// Creates a persistent Storage Root Key (SRK) under the specified
// hierarchy using the Endorsement Key (EK) to salt an HMAC session.
// Optionally encrypts bus communication between the CPU <-> TPM if
// enabled in the platform configuration file. If the HandleType is
// set to TPMHTTransient, the created objects handles are left
// unflushed and the caller is responsible for flushing it when
// done.
func (tpm *TPM2) CreateSRK(
	keyAttrs *keystore.KeyAttributes) error {

	tpmAttrs := keyAttrs.TPMAttributes
	hierarchy := tpm2.TPMHandle(tpmAttrs.Hierarchy)

	var primaryKey *tpm2.CreatePrimaryResponse
	var err error
	// var hierarchyAuth, userAuth []byte
	var hierarchyAuth, userAuth, secretBytes []byte

	if tpmAttrs.HierarchyAuth != nil {
		hierarchyAuth, err = tpmAttrs.HierarchyAuth.Bytes()
		if err != nil {
			return err
		}
	}
	if keyAttrs.Password != nil {
		userAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return err
		}
	}

	if keyAttrs.PlatformPolicy {
		tpmAttrs.Template.AuthPolicy = tpm.policyDigest
	}

	// Create SRK
	primaryKeyCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(tpmAttrs.Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: userAuth,
				},
			},
		},
	}

	// Attach PCR creation policy if platform policy is set
	if keyAttrs.PlatformPolicy {
		primaryKeyCMD.CreationPCR = tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash: tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(
						tpm.config.PlatformPCR),
				},
			},
		}
	}

	// // Add secret if provided, otherwise generate AES-256 key
	// if keyAttrs.Secret == nil {
	// 	tpm.logger.Info("Generating SRK seal secret")
	// 	secretBytes = aesgcm.NewAESGCM(
	// 		tpm.logger, tpm.debugSecrets, tpm).GenerateKey()

	// 	if keyAttrs.PlatformPolicy {
	// 		//  keyAttrs.Secret = NewPlatformSecret(tpm, keyAttrs)
	// 		keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
	// 	} else {
	// 		keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
	// 	}

	// } else {
	// 	secretBytes, err = keyAttrs.Secret.Bytes()
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// Add secret to creation data if provided
	if keyAttrs.Secret != nil {
		secretBytes, err = keyAttrs.Secret.Bytes()
		if err != nil {
			return err
		}
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("Sealing SRK secret: %s", secretBytes)
	}

	primaryKeyCMD.InSensitive.Sensitive.Data = tpm2.NewTPMUSensitiveCreate(
		&tpm2.TPM2BSensitiveData{
			Buffer: secretBytes,
		},
	)

	if tpm.config.EncryptSession && keyAttrs.Parent != nil {

		ekHandle := tpm2.TPMHandle(keyAttrs.Parent.TPMAttributes.Handle)

		// Get the persisted EK primary key to build salted HMAC session
		_, ekPub, err := tpm.ReadHandle(ekHandle)
		if err != nil {
			tpm.logger.Error(err)
			return err
		}

		// Create salted, (encrypted?) session using EK
		ekSession, closer, err := tpm.HMACSaltedSession(
			tpm2.TPMHandle(ekHandle),
			ekPub,
			// tpmAttrs.Parent.Password)
			nil)
		if err != nil {
			tpm.logger.Error(err)
			return err
		}
		if keyAttrs.TPMAttributes.HandleType == tpm2.TPMHTTransient {
			// Leave the session unflushed if this is a transient handle.
			// Set the closer so the caller can close the session when done
			//
			keyAttrs.TPMAttributes.SessionCloser = closer
		} else {
			defer closer()
		}

		primaryKey, err = primaryKeyCMD.Execute(tpm.transport, ekSession)

	} else {
		primaryKey, err = primaryKeyCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	// TODO: either the go-tpm lib or the TPM seems to return a nil
	// response without any errors when hierarchy authorization fails...
	if primaryKey == nil {
		// return ErrHierarchyAuthFailed
		return keystore.ErrSOPinRequired
	}

	tpm.logger.Debugf("tpm: Created SRK: 0x%x", primaryKey.ObjectHandle)

	if keyAttrs.TPMAttributes.HandleType == tpm2.TPMHTPersistent {

		// Make the SRK persistent
		_, err = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: hierarchy, // storage or platform
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			ObjectHandle: &tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   primaryKey.Name,
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			PersistentHandle: tpm2.TPMHandle(tpmAttrs.Handle),
		}.Execute(tpm.transport)

		tpm.Flush(primaryKey.ObjectHandle)

		if err != nil {
			tpm.logger.Error(err)
			return err
		}
		tpm.logger.Debugf("tpm: SRK persisted to 0x%x",
			tpm2.TPMHandle(tpmAttrs.Handle))

	} else {
		keyAttrs.TPMAttributes.Handle = primaryKey.ObjectHandle
	}

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	keyAttrs.KeyType = keystore.KEY_TYPE_STORAGE
	tpmAttrs.Name = primaryKey.Name
	tpmAttrs.Public = *pub

	tpm.logger.Debugf("tpm: SRK Hierarchy: %s", HierarchyName(hierarchy))
	tpm.logger.Debugf("tpm: SRK Name: 0x%s", Encode(primaryKey.Name.Buffer))

	return err
}

// Create an Initial Attestation Key
func (tpm *TPM2) CreateIAK(
	ekAttrs *keystore.KeyAttributes) (*keystore.KeyAttributes, error) {

	// + Endorsement Hierarchy
	//   - Endorsement Key
	//   - Attestation Key (restricted)
	//   - IDevID Key      (un-restricted)

	var hierarchyAuth, ekAuth, iakAuth, signature []byte
	var err error
	var isRSAPSS bool

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth, err = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
		if err != nil {
			return nil, err
		}
	}

	if ekAttrs.Password != nil {
		ekAuth, err = ekAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	// Create IAK key attributes from platform configuration file
	iakAttrs, err := IAKAttributesFromConfig(
		ekAttrs.TPMAttributes.HierarchyAuth,
		tpm.config.IAK,
		&tpm.policyDigest)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	iakAttrs.Parent = ekAttrs

	if iakAttrs.Password != nil {
		iakAuth, err = iakAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	// Build signing scheme based on key algorithm
	var inScheme tpm2.TPMTSigScheme
	if iakAttrs.KeyAlgorithm == x509.RSA {

		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
					HashAlg: iakAttrs.TPMAttributes.HashAlg,
				}),
		}

	} else {

		// ECDSA
		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: iakAttrs.TPMAttributes.HashAlg,
				},
			),
		}
	}

	// Define the AK template
	var template tpm2.TPMTPublic
	if iakAttrs.KeyAlgorithm == x509.RSA {
		if keystore.IsRSAPSS(iakAttrs.SignatureAlgorithm) {

			template = RSAPSSAKTemplate
			template.Parameters = tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSAPSS,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSAPSS,
							&tpm2.TPMSSigSchemeRSAPSS{
								HashAlg: iakAttrs.TPMAttributes.HashAlg,
							},
						),
					},
					KeyBits: tpm2.TPMKeyBits(iakAttrs.RSAAttributes.KeySize),
				},
			)
			inScheme = tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgRSAPSS,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgRSAPSS, &tpm2.TPMSSchemeHash{
						HashAlg: iakAttrs.TPMAttributes.HashAlg,
					}),
			}
			isRSAPSS = true
		} else {
			template = RSASSAAKTemplate
			template.Parameters = tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: iakAttrs.TPMAttributes.HashAlg,
							},
						),
					},
					KeyBits: tpm2.TPMKeyBits(iakAttrs.RSAAttributes.KeySize),
				},
			)
			inScheme = tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
						HashAlg: iakAttrs.TPMAttributes.HashAlg,
					}),
			}
		}

	} else if iakAttrs.KeyAlgorithm == x509.ECDSA {
		template = ECCAKP256Template
	}

	// Create PCR selection for creation data
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      iakAttrs.TPMAttributes.HashAlg,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			},
		},
	}
	iakAttrs.TPMAttributes.PCRSelection = pcrSelection

	// Create Attestation Primary Key
	iakPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: iakAuth,
				},
			},
		},
		CreationPCR: pcrSelection,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(iakPrimary.ObjectHandle)

	// Make the AK persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.AuthHandle{
			Handle: iakPrimary.ObjectHandle,
			Name:   iakPrimary.Name,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PersistentHandle: tpm2.TPMHandle(iakAttrs.TPMAttributes.Handle),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Extract public area
	iakPub, err := iakPrimary.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	// Certify the new IAK primary key
	certifyCreation := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: iakAttrs.TPMAttributes.Handle,
			Name:   iakPrimary.Name,
			Auth:   tpm2.PasswordAuth(ekAuth),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: iakAttrs.TPMAttributes.Handle,
			Name:   iakPrimary.Name,
		},
		CreationHash:   iakPrimary.CreationHash,
		InScheme:       inScheme,
		CreationTicket: iakPrimary.CreationTicket,
	}
	rspCC, err := certifyCreation.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}

	var akPublic crypto.PublicKey

	// Sign the attestation structure
	if iakPub.Type == tpm2.TPMAlgRSA {

		rsaDetail, err := iakPub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		rsaUnique, err := iakPub.Unique.RSA()
		if err != nil {
			return nil, err
		}

		akPublic, err = tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if isRSAPSS {
			rsaSig, err = rspCC.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = rspCC.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if iakPub.Type == tpm2.TPMAlgECC {

		sig, err := rspCC.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		ecDetail, err := iakPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		eccUnique, err := iakPub.Unique.ECC()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		akPublic = &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, err
		}
		signature = asn1Sig
	}

	akPublicDER, err := keystore.EncodePubKey(akPublic)
	if err != nil {
		return nil, err
	}

	iakAttrs.TPMAttributes.Name = iakPrimary.Name
	iakAttrs.TPMAttributes.CertifyInfo = rspCC.CertifyInfo.Bytes()
	iakAttrs.TPMAttributes.BPublic = iakPrimary.OutPublic
	iakAttrs.TPMAttributes.PublicKeyBytes = akPublicDER
	iakAttrs.TPMAttributes.CreationTicketDigest = iakPrimary.CreationTicket.Digest.Buffer
	iakAttrs.TPMAttributes.Signature = signature
	iakAttrs.TPMAttributes.Public = *iakPub

	// Cache the IAK
	tpm.iakAttrs = iakAttrs

	return iakAttrs, nil
}

// Creates an Initial Device IDentifier (IDevID) under the
// Endorsement Hierarchy per TCG - TPM 2.0 Keys for Device Identity
// and Attestation. The Endorsement Key (EK) attributes must contain
// the HierarchyAuth to authorize the creation of the IDevID key under
// the Endorsement hierarchy. The EK is also used to salt an HMAC
// session, and optionally encrypt the bus communication between the
// CPU <-> TPM if enabled in the platform configuration file.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
func (tpm *TPM2) CreateIDevID(
	akAttrs *keystore.KeyAttributes,
	ekCert *x509.Certificate) (*keystore.KeyAttributes, *TCG_CSR_IDEVID, error) {

	// + Endorsement Hierarchy
	//   - Endorsement Key
	//   - Attestation Key (restricted)
	//   - IDevID Key      (un-restricted)

	var hierarchyAuth, akAuth, idevidAuth, signature []byte
	var isRSAPSS bool

	if akAttrs.Parent == nil {
		return nil, nil, ErrInvalidEKAttributes
	}
	ekAttrs := akAttrs.Parent

	// if ekAttrs.Password != nil {
	// 	ekAuth, err = ekAttrs.Password.Bytes()
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// }

	// Create IDevID key attributes from platform configuration file
	idevidAttrs, err := IDevIDAttributesFromConfig(
		*tpm.config.IDevID, &tpm.policyDigest)
	if err != nil {
		return nil, nil, err
	}
	idevidAttrs.Parent = ekAttrs

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth, err = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
		if err != nil {
			return nil, nil, err
		}
	}

	if akAttrs.Password != nil {
		akAuth, err = akAttrs.Password.Bytes()
		if err != nil {
			return nil, nil, err
		}
	}

	if idevidAttrs.Password != nil {
		idevidAuth, err = idevidAttrs.Password.Bytes()
		if err != nil {
			return nil, nil, err
		}
	}

	var idevidTemplate tpm2.TPMTPublic
	if ekAttrs.KeyAlgorithm == x509.RSA {
		if keystore.IsRSAPSS(idevidAttrs.SignatureAlgorithm) {
			idevidTemplate = RSAPSSIDevIDTemplate
			isRSAPSS = true
		} else {
			idevidTemplate = RSASSAIDevIDTemplate
		}
	} else if idevidAttrs.KeyAlgorithm == x509.ECDSA {
		idevidTemplate = ECCIDevIDP256Template
	}

	// TPM 2.0 Keys for Device Identity and Attestation - Section 3.10 - Key
	// Authorizations: Applications using only Policy to control key
	// administration MUST SET the adminWithPolicy attribute when creating
	// the key. When adminWithPolicy is CLEAR, the authValue may be used in
	// an HMAC session to perform Admin operations.
	if idevidAttrs.Password == nil && idevidAttrs.PlatformPolicy {
		idevidTemplate.ObjectAttributes.AdminWithPolicy = true
	}

	// Create IDevID Key
	primaryKeyCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(idevidTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: idevidAuth,
				},
			},
		},
		CreationPCR: akAttrs.TPMAttributes.PCRSelection,
	}
	unique := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: []byte(idevidAttrs.CN),
		},
	)
	inPub, err := primaryKeyCMD.InPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	inPub.Unique = unique

	primaryKey, err := primaryKeyCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	// Make the IDevID Key persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PersistentHandle: tpm2.TPMHandle(idevidAttrs.TPMAttributes.Handle),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}

	// Extract public area
	idevidPub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	originalBuffer := []byte("test nonce")

	certify := tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(idevidAuth),
		},
		SignHandle: tpm2.AuthHandle{
			Handle: akAttrs.TPMAttributes.Handle,
			Name:   akAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(akAuth),
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: originalBuffer,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgNull,
		},
	}
	rspCert, err := certify.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	akPub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	var pubKeyBytes []byte

	// Sign the attestation structure
	if akPub.Type == tpm2.TPMAlgRSA {

		rsaDetail, err := idevidPub.Parameters.RSADetail()
		if err != nil {
			return nil, nil, err
		}
		rsaUnique, err := idevidPub.Unique.RSA()
		if err != nil {
			return nil, nil, err
		}

		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, nil, err
		}

		rsaDER, err := keystore.EncodePubKey(rsaPub)
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		pubKeyBytes = rsaDER

		var rsaSig *tpm2.TPMSSignatureRSA
		if isRSAPSS {
			rsaSig, err = rspCert.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, nil, err
			}
		} else {
			rsaSig, err = rspCert.Signature.Signature.RSASSA()
			if err != nil {
				return nil, nil, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if akPub.Type == tpm2.TPMAlgECC {

		sig, err := rspCert.Signature.Signature.ECDSA()
		if err != nil {
			return nil, nil, err
		}

		ecDetail, err := idevidPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		eccUnique, err := idevidPub.Unique.ECC()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		eccDER, err := keystore.EncodePubKey(eccPub)
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		pubKeyBytes = eccDER

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, nil, err
		}
		signature = asn1Sig
	}

	tpm.logger.Debug("tpm: IDevID Key Hierarchy: Endorsement")

	tpm.logger.Debugf(
		"tpm: IDevID Key persistent to handle 0x%x",
		idevidAttrs.TPMAttributes.Handle)

	tpm.logger.Debugf(
		"tpm: IDevID Key Name: %s",
		Encode(primaryKey.Name.Buffer))

	idevidAttrs.TPMAttributes.Name = primaryKey.Name
	idevidAttrs.TPMAttributes.BPublic = primaryKey.OutPublic
	idevidAttrs.TPMAttributes.CertifyInfo = rspCert.CertifyInfo.Bytes()
	idevidAttrs.TPMAttributes.PublicKeyBytes = pubKeyBytes
	idevidAttrs.TPMAttributes.Public = *idevidPub
	idevidAttrs.TPMAttributes.Signature = signature

	tcgCSR, err := tpm.CreateTCG_CSR_IDEVID(
		ekCert, akAttrs, idevidAttrs)
	if err != nil {
		return nil, nil, err
	}

	tpm.idevidAttrs = idevidAttrs

	return idevidAttrs, &tcgCSR, nil
}

func (tpm *TPM2) DeleteKey(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) error {

	// Ensure the caller owns the key
	_, err := tpm.Unseal(keyAttrs, backend)
	if err != nil {
		return err
	}

	// Delete the key pair from the backend
	if err := tpm.DeleteKeyPair(keyAttrs, backend); err != nil {
		tpm.logger.Error(err)
		return err
	}

	return nil
}
