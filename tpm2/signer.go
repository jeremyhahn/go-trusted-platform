package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	ErrReadPublic              = errors.New("signer: unable to read entity Public Area")
	ErrReadPublicContent       = errors.New("signer: unable to read entity Public Area Content")
	ErrReadPublicRSAParameters = errors.New("signer: unable to read Public RSA Parameters")
	ErrReadPublicRSAUnique     = errors.New("signer: unable to read Public RSA Unique")
	ErrCreatePublicRSA         = errors.New("signer: unable to create RSA Key Public Key")
	ErrReadPublicECCDetail     = errors.New("signer: unable to read ECC Public Area Detail")
	ErrReadPublicECCCurve      = errors.New("signer: unable to read ECC Curve Details")
	ErrReadPublicECCUnique     = errors.New("signer: unable to read Public Area ECC Unique")
	ErrUnsupportedKeyType      = errors.New("signer: unsupported key type")
)

type Signer struct {
	tpm         *TPM2
	transport   transport.TPM
	pubKey      crypto.PublicKey
	namedHandle tpm2.NamedHandle
	public      tpm2.TPMTPublic

	session tpm2.Session

	//AuthSession      Session
	EncryptionHandle tpm2.TPMHandle
	EncryptionPub    *tpm2.TPMTPublic
	refreshMutex     sync.Mutex
}

func NewSigner(tpm *TPM2, namedHandle tpm2.NamedHandle, session tpm2.Session) (Signer, error) {

	signer := Signer{
		transport:   tpm.transport,
		namedHandle: namedHandle,
		session:     session,
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: namedHandle.Handle,
	}.Execute(tpm.transport)
	if err != nil {
		return Signer{}, fmt.Errorf("%s: %v", ErrReadPublic, err)
	}

	pc, err := pub.OutPublic.Contents()
	if err != nil {
		return Signer{}, fmt.Errorf("%s: %v", ErrReadPublicContent, err)
	}
	signer.public = *pc

	if pc.Type == tpm2.TPMAlgRSA {
		rsaDetail, err := pc.Parameters.RSADetail()
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrReadPublicRSAParameters, err)
		}

		rsaUnique, err := pc.Unique.RSA()
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrReadPublicRSAUnique, err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrCreatePublicRSA, err)
		}
		signer.pubKey = rsaPub

	} else if pc.Type == tpm2.TPMAlgECC {

		ecDetail, err := pc.Parameters.ECCDetail()
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrReadPublicECCDetail, err)
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrReadPublicECCCurve, err)
		}
		eccUnique, err := pc.Unique.ECC()
		if err != nil {
			return Signer{}, fmt.Errorf("%s: %s", ErrReadPublicECCUnique, err)
		}
		signer.pubKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
	} else {
		return Signer{}, fmt.Errorf("%s: %v", ErrUnsupportedKeyType, pc.Type)
	}

	return signer, nil
}

func (s *Signer) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *Signer) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.refreshMutex.Lock()
	defer s.refreshMutex.Unlock()

	// if s.EncryptionHandle != 0 && s.EncryptionPub != nil {
	// 	sess = tpm2.HMAC(
	// 		tpm2.TPMAlgSHA256,
	// 		16,
	// 		tpm2.AESEncryption(
	// 			128,
	// 			tpm2.EncryptIn),
	// 		tpm2.Salted(s.EncryptionHandle, *s.EncryptionPub))
	// } else {
	// 	sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	// }

	var algid tpm2.TPMIAlgHash

	if opts == nil {
		algid = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			algid = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			algid = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			algid = tpm2.TPMAlgSHA512
		} else {
			return nil, fmt.Errorf("signer: unknown hash function %v", opts.HashFunc())
		}
	}
	defer s.session.Handle()

	// var se tpm2.Session
	// if s.AuthSession != nil {
	// 	var err error
	// 	se, err = s.AuthSession.GetSession()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("signer: error getting session %s", err)
	// 	}
	// 	defer func() {
	// 		_, err = (&tpm2.FlushContext{FlushHandle: se.Handle()}).Execute(s.transport)
	// 	}()
	// } else {
	// 	se = tpm2.PasswordAuth(nil)
	// }

	var tsig []byte
	switch s.pubKey.(type) {
	case *rsa.PublicKey:
		rd, err := s.public.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: s.namedHandle.Handle,
				Name:   s.namedHandle.Name,
				Auth:   s.session,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(s.transport, s.session)
		if err != nil {
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		var rsig *tpm2.TPMSSignatureRSA
		if rspSign.Signature.SigAlg == tpm2.TPMAlgRSASSA {
			rsig, err = rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa ssa signature: %v", err)
			}
		} else if rspSign.Signature.SigAlg == tpm2.TPMAlgRSAPSS {
			rsig, err = rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa pss signature: %v", err)
			}
		} else {
			return nil, fmt.Errorf("signer: unsupported signature algorithm't Sign: %v", err)
		}

		tsig = rsig.Sig.Buffer
	case *ecdsa.PublicKey:
		rd, err := s.public.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: s.namedHandle.Handle,
				Name:   s.namedHandle.Name,
				Auth:   s.session,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(s.transport, s.session)
		if err != nil {
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		rsig, err := rspSign.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("signer: error getting ecc signature: %v", err)
		}
		// if s.ECCRawOutput {
		tsig = append(rsig.SignatureR.Buffer, rsig.SignatureS.Buffer...)
		// } else {
		// 	r := big.NewInt(0).SetBytes(rsig.SignatureR.Buffer)
		// 	s := big.NewInt(0).SetBytes(rsig.SignatureS.Buffer)
		// 	sigStruct := struct{ R, S *big.Int }{r, s}
		// 	return asn1.Marshal(sigStruct)
		// }
	}

	return tsig, nil
}
