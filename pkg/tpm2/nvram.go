package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Seals a secret to an NV RAM index against the Platform Policy
func (tpm *TPM2) NVWrite(
	keyAttrs *keystore.KeyAttributes) error {

	var hierarchyAuth, secretBytes []byte
	// var secretBytes []byte
	var closer func() error
	var session tpm2.Session
	var err error

	if keyAttrs.TPMAttributes == nil {
		return keystore.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth, err = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
		if err != nil {
			return err
		}
	}

	secretBytes, err = keyAttrs.Secret.Bytes()
	if err != nil {
		return err
	}

	var policyDigest tpm2.TPM2BDigest
	var policyRead bool
	if keyAttrs.PlatformPolicy {
		policyDigest = tpm.policyDigest
		policyRead = true
	}

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: keyAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    tpm2.TPMHandle(keyAttrs.TPMAttributes.Handle),
				NameAlg:    keyAttrs.TPMAttributes.HashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: uint16(len(secretBytes)),
			}),
	}

	_, err = defs.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		return err
	}
	defer closer()

	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: keyAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   session,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: secretBytes,
		},
		Offset: 0,
	}
	if _, err := write.Execute(tpm.transport); err != nil {
		tpm.logger.Error(err)
		return err
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("NVWriteSecret: secret: %s", string(secretBytes))
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	return nil
}

// Unseals data from NV RAM index protected by the Platform PCR policy
func (tpm *TPM2) NVRead(
	keyAttrs *keystore.KeyAttributes,
	dataSize uint16) ([]byte, error) {

	var hierarchyAuth []byte
	var err error

	if keyAttrs.TPMAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth, err = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
		if err != nil {
			return nil, err
		}
	}

	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer closer()

	// Read the NV RAM bytes
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: keyAttrs.TPMAttributes.Handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	tpm.logger.Debugf("Name: %x", Encode(readPubRsp.NVName.Buffer))

	readRsp, err := tpm2.NVRead{
		// AuthHandle: tpm2.AuthHandle{
		// 	Handle: keyAttrs.TPMAttributes.Hierarchy,
		// 	Auth:   tpm2.PasswordAuth(hierarchyAuth),
		// },
		// NVIndex: tpm2.AuthHandle{
		// 	Handle: keyAttrs.TPMAttributes.Handle,
		// 	Name:   readPubRsp.NVName,
		// 	Auth:   session,
		// },
		AuthHandle: tpm2.AuthHandle{
			Handle: keyAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: keyAttrs.TPMAttributes.Handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
		},
		Size: dataSize,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("NVReadSecret: retrieved secret: %s", string(readRsp.Data.Buffer))

	return readRsp.Data.Buffer, nil
}

// // Unseals data from NV RAM index protected by the Platform PCR policy
// func (tpm *TPM2) NVReadWithoutPolicy(
// 	keyAttrs *keystore.KeyAttributes,
// 	dataSize uint16) ([]byte, error) {

// 	var session tpm2.Session
// 	var err error

// 	if keyAttrs.TPMAttributes == nil {
// 		return nil, keystore.ErrInvalidKeyAttributes
// 	}

// 	hierarchyAuth, err := keyAttrs.TPMAttributes.HierarchyAuth.Bytes()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create unencrypted, authenticated password session
// 	session = tpm2.PasswordAuth(hierarchyAuth)

// 	// Read the NV RAM bytes
// 	readPubRsp, err := tpm2.NVReadPublic{
// 		NVIndex: keyAttrs.TPMAttributes.Handle,
// 	}.Execute(tpm.transport)
// 	if err != nil {
// 		tpm.logger.Error(err)
// 		return nil, err
// 	}
// 	tpm.logger.Debugf("Name: %x", Encode(readPubRsp.NVName.Buffer))

// 	readRsp, err := tpm2.NVRead{
// 		AuthHandle: tpm2.AuthHandle{
// 			Handle: keyAttrs.TPMAttributes.Hierarchy,
// 			Name:   readPubRsp.NVName,
// 			Auth:   session,
// 		},
// 		NVIndex: tpm2.NamedHandle{
// 			Handle: keyAttrs.TPMAttributes.Handle,
// 			Name:   readPubRsp.NVName,
// 		},
// 		Size: dataSize,
// 	}.Execute(tpm.transport)
// 	if err != nil {
// 		tpm.logger.Error(err)
// 		return nil, err
// 	}

// 	tpm.logger.Debugf("NVReadSecret: retrieved secret: %s", string(readRsp.Data.Buffer))

// 	return readRsp.Data.Buffer, nil
// }
