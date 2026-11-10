package platform

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// errFakeTPMAuthFail is what the fake TPM returns for a wrong authorization
// value, as a real TPM answers TPM_RC_AUTH_FAIL.
type errFakeTPMAuthFail struct{}

func (errFakeTPMAuthFail) Error() string { return "fake tpm: authorization failed" }

// errFakeTPMProperties is the fake TPM's GetCapability failure.
type errFakeTPMProperties struct{}

func (errFakeTPMProperties) Error() string { return "fake tpm: fixed properties unavailable" }

// authTPM is a TPM fake that keeps one authorization value per handle and
// enforces it the way a real TPM does: VerifyAuth and ChangeAuth fail on a
// wrong value, and ChangeAuth installs the new one only after the current
// value checks out. It records the DA lockout reset and serves fixed
// properties for the lockout counters.
type authTPM struct {
	*mockTPM
	auth         map[tpm2.TPMHandle][]byte
	props        *xkmssdk.PropertiesFixed
	propsErr     error
	lockoutAuth  []byte
	lockoutReset bool
}

func newAuthTPM(handle tpm2.TPMHandle, pin string) *authTPM {
	return &authTPM{
		mockTPM: &mockTPM{
			keyAttributesFunc: func(tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
				return nil, errors.New("key not found")
			},
			ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
				return &xkmssdk.KeyAttributes{CN: "ek"}, nil
			},
			createSRKFunc: func(*xkmssdk.KeyAttributes) error { return nil },
		},
		auth: map[tpm2.TPMHandle][]byte{handle: []byte(pin)},
	}
}

func (f *authTPM) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	current, ok := f.auth[handle]
	if !ok || !bytes.Equal(current, authValue) {
		return errFakeTPMAuthFail{}
	}
	return nil
}

func (f *authTPM) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	if err := f.VerifyAuth(handle, currentAuth); err != nil {
		return err
	}
	f.auth[handle] = append([]byte(nil), newAuth...)
	return nil
}

func (f *authTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return f.props, f.propsErr
}

func (f *authTPM) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	if !bytes.Equal(lockoutAuth, f.lockoutAuth) {
		return errFakeTPMAuthFail{}
	}
	f.lockoutReset = true
	return nil
}

const testPlatformSRKHandle = 0x81000002

// newAuthKeyStore builds a PlatformKeyStore over an authTPM whose Platform
// SRK carries pin. The SRK is not yet persisted, so the store starts
// uninitialized.
func newAuthKeyStore(t *testing.T, pin string, policy bool) (*PlatformKeyStore, *authTPM) {
	t.Helper()
	fake := newAuthTPM(tpm2.TPMHandle(testPlatformSRKHandle), pin)
	ks, err := NewPlatformKeyStore(fake, &mockKeyBackend{}, &xkmssdk.PlatformSRKConfig{
		CN:             "platform-srk",
		SRKHandle:      testPlatformSRKHandle,
		PlatformPolicy: policy,
	})
	require.ErrorIs(t, err, ErrXKMSNotInitialized)
	require.NotNil(t, ks)
	return ks, fake
}

func TestPlatformKeyStore_InitializeWithDefaults(t *testing.T) {
	t.Run("creates the SRK with empty auth under the EK", func(t *testing.T) {
		ks, fake := newAuthKeyStore(t, "", false)
		var created *xkmssdk.KeyAttributes
		fake.createSRKFunc = func(attrs *xkmssdk.KeyAttributes) error {
			created = attrs
			return nil
		}

		require.False(t, ks.IsInitialized())
		require.NoError(t, ks.InitializeWithDefaults())

		assert.True(t, ks.IsInitialized())
		assert.True(t, ks.IsProvisioned())
		assert.True(t, ks.IsAuthReady())
		assert.Nil(t, ks.PINBackend(), "defaults skip the PIN backend")
		require.NotNil(t, created)
		require.NotNil(t, created.Parent)
		assert.Equal(t, "ek", created.Parent.CN)
		require.NotNil(t, created.TPMAttributes)
		assert.Equal(t, tpm2.TPMHandle(testPlatformSRKHandle), created.TPMAttributes.Handle)
		assert.Empty(t, created.Password.Bytes())
		assert.Empty(t, created.TPMAttributes.HierarchyAuth.Bytes())
	})

	ekErr := errors.New("ek unavailable")
	srkErr := errors.New("nv space full")
	tests := []struct {
		name    string
		cn      string
		ekErr   error
		srkErr  error
		wantErr error
	}{
		{name: "missing CN", cn: "", wantErr: ErrInvalidXKMSCN},
		{name: "EK attributes fail", cn: "platform-srk", ekErr: ekErr, wantErr: ekErr},
		{name: "SRK creation fails", cn: "platform-srk", srkErr: srkErr, wantErr: srkErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, fake := newAuthKeyStore(t, "", false)
			ks.config.CN = tt.cn
			fake.ekAttributesFunc = func() (*xkmssdk.KeyAttributes, error) {
				if tt.ekErr != nil {
					return nil, tt.ekErr
				}
				return &xkmssdk.KeyAttributes{CN: "ek"}, nil
			}
			fake.createSRKFunc = func(*xkmssdk.KeyAttributes) error { return tt.srkErr }

			err := ks.InitializeWithDefaults()

			require.ErrorIs(t, err, tt.wantErr)
			assert.NotEmpty(t, err.Error())
			assert.False(t, ks.IsInitialized(), "a failed initialization must not mark the store ready")
		})
	}
}

func TestPlatformKeyStore_EnrollPlatformSRK(t *testing.T) {
	t.Run("rejects an empty user PIN", func(t *testing.T) {
		ks, _ := newAuthKeyStore(t, "", false)
		assert.ErrorIs(t, ks.EnrollPlatformSRK("so", ""), xkmssdk.ErrPlatformSRKEnrollEmptyPIN)
		assert.False(t, ks.IsAuthReady())
	})

	t.Run("enrolls once and is idempotent afterwards", func(t *testing.T) {
		ks, fake := newAuthKeyStore(t, "", false)
		creates := 0
		fake.createSRKFunc = func(*xkmssdk.KeyAttributes) error {
			creates++
			return nil
		}

		require.NoError(t, ks.EnrollPlatformSRK("so", "1234"))
		assert.True(t, ks.IsAuthReady())
		assert.ErrorIs(t, ks.EnrollPlatformSRK("so", "1234"), xkmssdk.ErrPlatformSRKAlreadyEnrolled)
		assert.Equal(t, 1, creates, "a second enrollment must not recreate the SRK")
	})

	t.Run("an SRK the TPM refuses stays unenrolled", func(t *testing.T) {
		ks, fake := newAuthKeyStore(t, "", false)
		refused := errors.New("owner auth fail")
		fake.createSRKFunc = func(*xkmssdk.KeyAttributes) error { return refused }

		assert.ErrorIs(t, ks.EnrollPlatformSRK("so", "1234"), refused)
		assert.False(t, ks.IsAuthReady())
	})
}

func TestPlatformKeyStore_SetAuthReady(t *testing.T) {
	ks, _ := newAuthKeyStore(t, "", false)
	require.False(t, ks.IsAuthReady())

	ks.SetAuthReady(true)
	assert.True(t, ks.IsAuthReady())
	assert.True(t, ks.IsInitialized())

	ks.SetAuthReady(false)
	assert.False(t, ks.IsAuthReady())
	assert.False(t, ks.IsProvisioned())
}

func TestPlatformKeyStore_PlatformPolicyEnabled(t *testing.T) {
	enabled, _ := newAuthKeyStore(t, "", true)
	disabled, _ := newAuthKeyStore(t, "", false)

	assert.True(t, enabled.PlatformPolicyEnabled())
	assert.False(t, disabled.PlatformPolicyEnabled())
	assert.False(t, (&PlatformKeyStore{}).PlatformPolicyEnabled(), "a store without config has no policy")
}

func TestPlatformKeyStore_VerifyAuth(t *testing.T) {
	t.Run("refuses before initialization", func(t *testing.T) {
		ks, _ := newAuthKeyStore(t, "1234", false)
		assert.ErrorIs(t, ks.VerifyAuth("1234"), ErrXKMSNotInitialized)
	})

	t.Run("checks the PIN against the SRK handle", func(t *testing.T) {
		ks, _ := newAuthKeyStore(t, "1234", false)
		ks.SetAuthReady(true)

		assert.NoError(t, ks.VerifyAuth("1234"))
		assert.ErrorAs(t, ks.VerifyAuth("9999"), &errFakeTPMAuthFail{})
	})
}

func TestPlatformKeyStore_ChangeAuth(t *testing.T) {
	t.Run("refuses before initialization", func(t *testing.T) {
		ks, fake := newAuthKeyStore(t, "1234", false)
		assert.ErrorIs(t, ks.ChangeAuth("1234", "5678"), ErrXKMSNotInitialized)
		assert.Equal(t, []byte("1234"), fake.auth[testPlatformSRKHandle])
	})

	t.Run("rotates the PIN on the SRK handle", func(t *testing.T) {
		ks, _ := newAuthKeyStore(t, "1234", false)
		ks.SetAuthReady(true)

		require.NoError(t, ks.ChangeAuth("1234", "5678"))
		assert.NoError(t, ks.VerifyAuth("5678"))
		assert.ErrorAs(t, ks.VerifyAuth("1234"), &errFakeTPMAuthFail{}, "the old PIN must stop working")
	})

	t.Run("a wrong current PIN leaves the PIN unchanged", func(t *testing.T) {
		ks, _ := newAuthKeyStore(t, "1234", false)
		ks.SetAuthReady(true)

		assert.ErrorAs(t, ks.ChangeAuth("0000", "5678"), &errFakeTPMAuthFail{})
		assert.NoError(t, ks.VerifyAuth("1234"))
	})
}

func TestPlatformKeyStore_GetLockoutInfo(t *testing.T) {
	t.Run("reports the TPM counters", func(t *testing.T) {
		ks, fake := newAuthKeyStore(t, "", false)
		fake.props = &xkmssdk.PropertiesFixed{
			LockoutCounter:  3,
			MaxAuthFail:     32,
			LockoutInterval: 7200,
			LockoutRecovery: 86400,
		}

		failed, maxFail, interval, recovery, err := ks.GetLockoutInfo()
		require.NoError(t, err)
		assert.Equal(t, []int{3, 32, 7200, 86400}, []int{failed, maxFail, interval, recovery})
	})

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "properties error", err: errFakeTPMProperties{}, wantErr: true},
		{name: "no properties", err: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name+" falls back to defaults", func(t *testing.T) {
			ks, fake := newAuthKeyStore(t, "", false)
			fake.propsErr = tt.err

			failed, maxFail, interval, recovery, err := ks.GetLockoutInfo()
			if tt.wantErr {
				assert.ErrorAs(t, err, &errFakeTPMProperties{})
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, []int{0, 10, 0, 300}, []int{failed, maxFail, interval, recovery})
		})
	}
}

func TestPlatformKeyStore_DictionaryAttackLockoutReset(t *testing.T) {
	ks, fake := newAuthKeyStore(t, "", false)
	fake.lockoutAuth = []byte("lockout")

	assert.ErrorAs(t, ks.DictionaryAttackLockoutReset([]byte("wrong")), &errFakeTPMAuthFail{})
	assert.False(t, fake.lockoutReset)

	require.NoError(t, ks.DictionaryAttackLockoutReset([]byte("lockout")))
	assert.True(t, fake.lockoutReset)
}

func TestXKMS_GenerateKey_AlgorithmDispatch(t *testing.T) {
	kc, err := NewXKMS(slog.Default(), &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}, nil, xkmssdk.NewStorageMemory(), xkmssdk.NewStorageMemory(), nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, kc.Close()) })

	t.Run("ECDSA", func(t *testing.T) {
		key, err := kc.GenerateKey(context.Background(), &xkmssdk.KeyAttributes{
			CN:            "ecdsa-key",
			StoreType:     xkmssdk.StoreSoftware,
			KeyAlgorithm:  x509.ECDSA,
			KeyType:       xkmssdk.KeyTypeSigning,
			ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		})
		require.NoError(t, err)
		signer, ok := key.(crypto.Signer)
		require.True(t, ok)
		_, isECDSA := signer.Public().(*ecdsa.PublicKey)
		assert.True(t, isECDSA)
	})

	t.Run("Ed25519", func(t *testing.T) {
		key, err := kc.GenerateKey(context.Background(), &xkmssdk.KeyAttributes{
			CN:           "ed25519-key",
			StoreType:    xkmssdk.StoreSoftware,
			KeyAlgorithm: x509.Ed25519,
			KeyType:      xkmssdk.KeyTypeSigning,
		})
		require.NoError(t, err)
		signer, ok := key.(crypto.Signer)
		require.True(t, ok)
		_, isEd25519 := signer.Public().(ed25519.PublicKey)
		assert.True(t, isEd25519)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		key, err := kc.GenerateKey(context.Background(), &xkmssdk.KeyAttributes{
			CN:           "dsa-key",
			StoreType:    xkmssdk.StoreSoftware,
			KeyAlgorithm: x509.DSA,
		})
		assert.Nil(t, key)
		var unsupported ErrUnsupportedKeyAlgorithm
		require.ErrorAs(t, err, &unsupported)
		assert.Equal(t, x509.DSA, unsupported.Algorithm)
		assert.Contains(t, err.Error(), "unsupported key algorithm")
	})
}

func TestTypedErrors_MessagesAndCauses(t *testing.T) {
	cause := errors.New("pcr read failed")

	policy := ErrPlatformPolicyFailed{Cause: cause}
	assert.ErrorIs(t, policy, cause)
	assert.Contains(t, policy.Error(), "platform policy digest")
	assert.Contains(t, policy.Error(), cause.Error())

	msg := &MessageError{Msg: "registry: boom"}
	assert.Equal(t, "registry: boom", msg.Error())

	sentinel := &SentinelCauseError{Sentinel: ErrInvalidXKMSCN, Cause: cause}
	assert.ErrorIs(t, sentinel, ErrInvalidXKMSCN)
	assert.ErrorIs(t, sentinel, cause)
	assert.Equal(t, ErrInvalidXKMSCN.Error()+": "+cause.Error(), sentinel.Error())

	wrapped := &WrappedError{Msg: "failed to seal", Err: cause}
	assert.Same(t, cause, errors.Unwrap(wrapped))

	pubKeyErr := &ErrTPMSignerPublicKey{CN: "idevid", Err: cause}
	var asPubKey *ErrTPMSignerPublicKey
	require.ErrorAs(t, error(pubKeyErr), &asPubKey)
	assert.Contains(t, pubKeyErr.Error(), `"idevid"`)
	assert.ErrorIs(t, pubKeyErr, cause)
}
