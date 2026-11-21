package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// raceFreeBundleCA serves a fixed bundle without recording the call, so
// concurrent CABundle reads stay race free under -race.
type raceFreeBundleCA struct {
	*configurableMockCA
}

func (m *raceFreeBundleCA) CABundle() ([]byte, error) { return m.bundle, nil }

func requireCANotInitialized(t *testing.T, err error) {
	t.Helper()
	var notInit ErrCANotInitialized
	require.Error(t, err)
	assert.True(t, errors.As(err, &notInit), "want ErrCANotInitialized, got %v", err)
}

func TestCAHolder_AKTrust_FollowsTheSwap(t *testing.T) {
	var nilHolder *CAHolder
	assert.Nil(t, nilHolder.AKTrust())

	holder := NewCAHolder(nil)
	anchor := holder.AKTrust()
	require.NotNil(t, anchor)

	_, err := anchor.TrustedRoot()
	requireCANotInitialized(t, err)
	_, err = anchor.TrustedIntermediate()
	requireCANotInitialized(t, err)

	caA := lifecycleCA(t)
	holder.Set(caA)
	root, err := anchor.TrustedRoot()
	require.NoError(t, err)
	assert.Same(t, caA.trustedRoot, root)
	inter, err := anchor.TrustedIntermediate()
	require.NoError(t, err)
	assert.Same(t, caA.trustedInter, inter)

	caB := lifecycleCA(t)
	holder.Set(caB)
	root, err = anchor.TrustedRoot()
	require.NoError(t, err)
	assert.Same(t, caB.trustedRoot, root)
	inter, err = anchor.TrustedIntermediate()
	require.NoError(t, err)
	assert.Same(t, caB.trustedInter, inter)
}

func TestCAHolder_BootCA_FollowsTheSwap(t *testing.T) {
	var nilHolder *CAHolder
	assert.Nil(t, nilHolder.BootCA())

	holder := NewCAHolder(nil)
	boot := holder.BootCA()
	require.NotNil(t, boot)

	_, err := boot.CABundle()
	requireCANotInitialized(t, err)

	holder.Set(&configurableMockCA{isInitialized: true, bundle: []byte("bundle-a")})
	got, err := boot.CABundle()
	require.NoError(t, err)
	assert.Equal(t, []byte("bundle-a"), got)

	holder.Set(&configurableMockCA{isInitialized: true, bundle: []byte("bundle-b")})
	got, err = boot.CABundle()
	require.NoError(t, err)
	assert.Equal(t, []byte("bundle-b"), got)

	bundleErr := errors.New("bundle unavailable")
	holder.Set(&configurableMockCA{isInitialized: true, bundleErr: bundleErr})
	_, err = boot.CABundle()
	assert.ErrorIs(t, err, bundleErr)
}

func TestCAHolder_TrustConcurrentSwap(t *testing.T) {
	caA := &raceFreeBundleCA{lifecycleCA(t)}
	caA.bundle = []byte("bundle-a")
	caB := &raceFreeBundleCA{lifecycleCA(t)}
	caB.bundle = []byte("bundle-b")

	holder := NewCAHolder(caA)
	anchor := holder.AKTrust()
	boot := holder.BootCA()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if (i+j)%2 == 0 {
					holder.Set(caA)
				} else {
					holder.Set(caB)
				}
			}
		}(i)
	}

	errs := make(chan string, 16*50*2)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				root, err := anchor.TrustedRoot()
				if err == nil && root != caA.trustedRoot && root != caB.trustedRoot {
					errs <- "root is neither CA's root"
				}
				bundle, err := boot.CABundle()
				if err == nil && string(bundle) != "bundle-a" && string(bundle) != "bundle-b" {
					errs <- "bundle is neither CA's bundle: " + string(bundle)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func ldevidSwapRequest() *platformv1.CreateLDevIDRequest {
	return &platformv1.CreateLDevIDRequest{
		Template:     &platformv1.CSRTemplate{CommonName: "device-01-ldevid"},
		Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		Profile:      "ldevid",
		ValidityDays: 90,
	}
}

func ldevidSwapCA(t *testing.T) *ldevidMockCA {
	t.Helper()
	now := time.Now()
	return &ldevidMockCA{cert: ldevidTestCert(t, "device-01-ldevid", now, now.Add(90*24*time.Hour))}
}

func TestCreateLDevID_CASourceFollowsTheSwap(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))
	holder := NewCAHolder(nil)
	svc.SetCASource(holder.Get)

	_, err := svc.CreateLDevID(context.Background(), ldevidSwapRequest())
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)
	assert.Equal(t, (ErrLDevIDCANotConfigured{}).Error(), status.Convert(err).Message())

	caA := ldevidSwapCA(t)
	holder.Set(caA)
	resp, err := svc.CreateLDevID(context.Background(), ldevidSwapRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetCertificatePem())
	assert.NotEmpty(t, caA.gotCSR, "caA did not receive the CSR")

	caB := ldevidSwapCA(t)
	holder.Set(caB)
	_, err = svc.CreateLDevID(context.Background(), ldevidSwapRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, caB.gotCSR, "caB did not receive the next CSR")

	t.Run("nil source keeps the SetCAService CA", func(t *testing.T) {
		svc := newLDevIDTestService(t)
		svc.SetTPM2Service(ldevidHappyTPM(t))
		ca := ldevidSwapCA(t)
		svc.SetCAService(ca)
		svc.SetCASource(nil)

		_, err := svc.CreateLDevID(context.Background(), ldevidSwapRequest())
		require.NoError(t, err)
		assert.NotEmpty(t, ca.gotCSR)
	})
}
