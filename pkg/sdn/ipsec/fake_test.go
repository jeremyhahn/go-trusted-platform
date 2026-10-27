// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"maps"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
)

var (
	errInjected = errors.New("injected failure")
	errNotFound = errors.New("configuration not found")
)

// validConfig is an enabled, valid overlay.ipsec section with two static
// peers.
func validConfig() *config.Config {
	return &config.Config{
		Enabled:         true,
		FabricInterface: "bond0",
		LocalAddress:    "10.20.0.11",
		StaticPeers:     []string{"10.20.0.1", "10.20.0.2"},
		Token:           config.TokenConfig{Handle: "6970736563"},
	}
}

// fakeSession models the part of charon a command session drives: the
// loaded connections, the IKE_SAs of each, and the credentials.
type fakeSession struct {
	conns    map[string]*Connection
	sas      map[string][]IKESA // connection → its IKE_SAs
	commands []string
	killed   []string // terminated IKE_SA unique IDs
	certs    []Credential
	tokens   []TokenKey
	pins     [][]byte // the PIN each load-token logged in with; nil for none
	fail     map[string]error
	done     chan struct{}
	closed   bool
}

func newFakeSession(held ...string) *fakeSession {
	f := &fakeSession{
		conns: make(map[string]*Connection),
		sas:   make(map[string][]IKESA),
		fail:  make(map[string]error),
		done:  make(chan struct{}),
	}
	for _, name := range held {
		f.conns[name] = &Connection{}
	}
	return f
}

func (f *fakeSession) record(command string) error {
	f.commands = append(f.commands, command)
	return f.fail[command]
}

func (f *fakeSession) LoadConn(_ context.Context, name string, conn *Connection) error {
	if err := f.record("load-conn"); err != nil {
		return err
	}
	f.conns[name] = conn
	return nil
}

func (f *fakeSession) UnloadConn(_ context.Context, name string) error {
	if err := f.record("unload-conn"); err != nil {
		return err
	}
	if _, ok := f.conns[name]; !ok {
		return errNotFound
	}
	delete(f.conns, name)
	return nil
}

func (f *fakeSession) Conns(context.Context) ([]string, error) {
	if err := f.record("get-conns"); err != nil {
		return nil, err
	}
	return f.loaded(), nil
}

func (f *fakeSession) IKESAs(_ context.Context, conn string) ([]HeldSA, error) {
	if err := f.record("list-sas"); err != nil {
		return nil, err
	}
	var out []HeldSA
	for _, name := range slices.Sorted(maps.Keys(f.sas)) {
		if conn != "" && name != conn {
			continue
		}
		for _, sa := range f.sas[name] {
			out = append(out, HeldSA{Conn: name, SA: sa})
		}
	}
	return out, nil
}

func (f *fakeSession) TerminateIKE(_ context.Context, uniqueID string) error {
	if err := f.record("terminate"); err != nil {
		return err
	}
	f.killed = append(f.killed, uniqueID)
	for name, sas := range f.sas {
		f.sas[name] = slices.DeleteFunc(sas, func(sa IKESA) bool { return sa.UniqueID == uniqueID })
	}
	return nil
}

func (f *fakeSession) LoadCert(_ context.Context, cred Credential) error {
	command := "load-cert"
	if cred.Kind == CredentialCRL {
		command = "load-crl"
	}
	if err := f.record(command); err != nil {
		return err
	}
	f.certs = append(f.certs, cred)
	return nil
}

func (f *fakeSession) LoadToken(_ context.Context, key TokenKey, pin *secure.Secret) error {
	if err := f.record("load-token"); err != nil {
		return err
	}
	f.tokens = append(f.tokens, key)
	if pin == nil {
		f.pins = append(f.pins, nil)
		return nil
	}
	buf, err := pin.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	f.pins = append(f.pins, slices.Clone(buf.Bytes()))
	return nil
}

func (f *fakeSession) Done() <-chan struct{} { return f.done }

func (f *fakeSession) Close() error {
	f.closed = true
	return f.fail["close"]
}

func (f *fakeSession) loaded() []string {
	return slices.Sorted(maps.Keys(f.conns))
}

// crls returns the DER of the CRLs loaded, in order.
func (f *fakeSession) crls() [][]byte {
	var out [][]byte
	for _, c := range f.certs {
		if c.Kind == CredentialCRL {
			out = append(out, c.DER)
		}
	}
	return out
}

// fakeIdentity is an IdentityProvider handing out a fixed identity.
type fakeIdentity struct {
	id     *TunnelIdentity
	err    error
	closed bool
}

func (f *fakeIdentity) TunnelIdentity(context.Context) (*TunnelIdentity, error) {
	return f.id, f.err
}

func (f *fakeIdentity) Close() { f.closed = true }

// fakeAnchor is an AnchorSource holding certs, or failing with err.
type fakeAnchor struct {
	certs []*x509.Certificate
	err   error
}

func (f *fakeAnchor) Certificates(context.Context) ([]*x509.Certificate, error) {
	return f.certs, f.err
}

// testPKI is a CA and a tunnel certificate it issued for 10.20.0.11, the
// local address of validConfig. ca is a root, or, under root, an
// intermediate.
type testPKI struct {
	ca     *x509.Certificate
	caKey  crypto.Signer
	root   *x509.Certificate // nil when ca is the root
	leaf   *x509.Certificate
	issued time.Time
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	issued := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	caKey := newKey(t)
	ca := createCert(t, caTemplate("tunnel CA", issued), nil, caKey, nil)
	leaf := createCert(t, leafTemplate(issued), ca, newKey(t), caKey)
	return &testPKI{ca: ca, caKey: caKey, leaf: leaf, issued: issued}
}

// intermediate is a PKI whose CA, named name, is an intermediate issued by
// p's root CA, with a tunnel certificate of its own: the PKI after a
// renewal that changed the intermediate.
func (p *testPKI) intermediate(t *testing.T, name string) *testPKI {
	t.Helper()
	key := newKey(t)
	ca := createCert(t, caTemplate(name, p.issued), p.ca, key, p.caKey)
	leaf := createCert(t, leafTemplate(p.issued), ca, newKey(t), key)
	return &testPKI{ca: ca, caKey: key, root: p.ca, leaf: leaf, issued: p.issued}
}

func caTemplate(name string, issued time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             issued,
		NotAfter:              issued.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTemplate(issued time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(0x2a),
		Subject:      pkix.Name{CommonName: "10.20.0.11"},
		NotBefore:    issued,
		NotAfter:     issued.Add(72 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("10.20.0.11")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// identity is the PKI's tunnel identity, with pin as its PIN: the leaf,
// its CA, then the root above that CA if there is one.
func (p *testPKI) identity(pin *secure.Secret) *TunnelIdentity {
	chain := []*x509.Certificate{p.leaf, p.ca}
	if p.root != nil {
		chain = append(chain, p.root)
	}
	return &TunnelIdentity{
		Chain: chain,
		Token: TokenKey{Slot: 0, KeyID: []byte("ipsec")},
		PIN:   pin,
	}
}

// crl is a CRL of the CA with the given number and thisUpdate.
func (p *testPKI) crl(t *testing.T, number int64, thisUpdate time.Time) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(24 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, p.ca, p.caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	return der
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// createCert signs tmpl with parentKey as parent, or self-signs it when
// parent is nil.
func createCert(t *testing.T, tmpl, parent *x509.Certificate, key *ecdsa.PrivateKey, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// newSecret seals a copy of s.
func newSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()
	pin, err := secure.NewSecret([]byte(s))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	t.Cleanup(pin.Destroy)
	return pin
}
