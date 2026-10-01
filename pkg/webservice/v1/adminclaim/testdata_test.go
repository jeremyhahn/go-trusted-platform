// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package adminclaim

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const testTenantID = "system"

// testAdminEmail is the admin account's email — the identifier the FIDO2
// ceremony enrols against. It is deliberately distinct from the admin
// USERNAME: the backbone resolves the account with GetByEmail and does not
// accept a username, so a fixture that reused the username would not
// exercise the real contract.
const testAdminEmail = "admin@test.invalid"

// pki is a throwaway CA plus the leaves a test needs.
type pki struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	pool     *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &pki{rootCert: cert, rootKey: key, pool: pool}
}

type leafOptions struct {
	commonName string
	spiffeURI  string
	notBefore  time.Time
	notAfter   time.Time
	extKeyUsse []x509.ExtKeyUsage
	selfSigned bool
}

// issue mints a leaf certificate and returns it with its signer.
func (p *pki) issue(t *testing.T, opts leafOptions) (*x509.Certificate, []byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Minute)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(time.Hour)
	}
	if opts.extKeyUsse == nil {
		opts.extKeyUsse = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.commonName},
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  opts.extKeyUsse,
	}
	if opts.spiffeURI != "" {
		uri, err := url.Parse(opts.spiffeURI)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{uri}
	}
	parent, parentKey := p.rootCert, crypto.Signer(p.rootKey)
	if opts.selfSigned {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, certPEM, key
}

// adminLeaf issues the canonical firstboot admin certificate shape.
func (p *pki) adminLeaf(t *testing.T) (*x509.Certificate, []byte, crypto.Signer) {
	t.Helper()
	return p.issue(t, leafOptions{
		commonName: "admin",
		spiffeURI:  "spiffe://example.internal/tenant/system/user/admin",
	})
}

func signChallenge(t *testing.T, signer crypto.Signer, challenge string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(challenge))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	return sig
}

// ---- SDK fakes -------------------------------------------------------

type fakeCeremony struct {
	beginResp   *quicbaassdk.FIDO2BeginRegistrationResponse
	beginErr    error
	finishResp  *quicbaassdk.FIDO2FinishRegistrationResponse
	finishErr   error
	beginCalls  int
	finishCalls atomic.Int64
	// onFinish, when set, runs inside FinishRegistration. Concurrency
	// tests use it to make the enrolment observable to the fake factor
	// lister, the way a real enrolment becomes visible to Factors().List.
	onFinish func()
}

func (f *fakeCeremony) BeginRegistration(
	ctx context.Context, req *quicbaassdk.FIDO2BeginRegistrationRequest) (
	*quicbaassdk.FIDO2BeginRegistrationResponse, error) {

	f.beginCalls++
	return f.beginResp, f.beginErr
}

func (f *fakeCeremony) FinishRegistration(
	ctx context.Context, req *quicbaassdk.FIDO2FinishRegistrationRequest) (
	*quicbaassdk.FIDO2FinishRegistrationResponse, error) {

	f.finishCalls.Add(1)
	if f.onFinish != nil {
		f.onFinish()
	}
	return f.finishResp, f.finishErr
}

type fakeFactors struct {
	mu   sync.Mutex
	resp *quicbaassdk.AuthFactorListResponse
	err  error
}

func (f *fakeFactors) List(ctx context.Context, userID string) (
	*quicbaassdk.AuthFactorListResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resp, f.err
}

// enrolFIDO2 makes a passkey visible to subsequent List calls, standing in
// for the SDK's write-through enrolment.
func (f *fakeFactors) enrolFIDO2() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp = &quicbaassdk.AuthFactorListResponse{
		Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "fido2"}},
	}
}

// fakeUsers is an in-memory service.UserServicer.
type fakeUsers struct {
	mu      sync.Mutex
	byID    map[uint64]*entities.User
	saveErr error
	getErr  error
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byID: map[uint64]*entities.User{}}
}

func (f *fakeUsers) Save(ctx context.Context, user *entities.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.byID[user.ID] = user
	return nil
}

func (f *fakeUsers) Delete(ctx context.Context, userID uint64) error {
	delete(f.byID, userID)
	return nil
}

func (f *fakeUsers) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	user, ok := f.byID[userID]
	if !ok {
		return nil, errNotFound
	}
	return user, nil
}

func (f *fakeUsers) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	for _, u := range f.byID {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, errNotFound
}

func (f *fakeUsers) GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error) {
	users := make([]*entities.User, 0, len(f.byID))
	for _, u := range f.byID {
		if u.TenantID == tenantID {
			users = append(users, u)
		}
	}
	return users, nil
}

func (f *fakeUsers) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	user, ok := f.byID[userID]
	return ok && user.IsTenantOwner, nil
}

// errNotFound is the store's real absence signal, so the fake exercises
// the same classification path production does — a fake with a bespoke
// error would let materialiseAdmin's fail-closed branch go untested.
var errNotFound = datastore.ErrRecordNotFound

type fakeIssuer struct {
	token string
	err   error
	user  *entities.User
}

func (f *fakeIssuer) GenerateToken(user *entities.User) (string, error) {
	f.user = user
	return f.token, f.err
}
