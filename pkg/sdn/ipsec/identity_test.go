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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTunnelIdentityValidate(t *testing.T) {
	pki := newTestPKI(t)
	local := addr("10.20.0.11")
	if err := pki.identity(nil).validate(local); err != nil {
		t.Fatalf("validate: %v", err)
	}
	mapped := pki.identity(nil)
	mapped.Chain[0] = &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.20.0.11").To16()}}
	if err := mapped.validate(local); err != nil {
		t.Fatalf("validate(16-byte SAN): %v", err)
	}

	noKey := pki.identity(nil)
	noKey.Token.KeyID = nil
	tests := []struct {
		name string
		id   *TunnelIdentity
		want error
	}{
		{"nil", nil, ErrNoCertificate},
		{"no chain", &TunnelIdentity{Token: TokenKey{KeyID: []byte{1}}}, ErrNoCertificate},
		{"nil leaf", &TunnelIdentity{Chain: []*x509.Certificate{nil}, Token: TokenKey{KeyID: []byte{1}}}, ErrNoCertificate},
		{"no key", noKey, ErrNoKeyID},
		{"another address", &TunnelIdentity{Chain: []*x509.Certificate{pki.ca}, Token: TokenKey{KeyID: []byte{1}}}, ErrCertificateAddress},
	}
	for _, tt := range tests {
		if err := tt.id.validate(local); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

// writeFile writes data to a fresh file and returns its path.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func pemChain(certs ...*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, c := range certs {
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return out.Bytes()
}

func TestFileIdentity(t *testing.T) {
	pki := newTestPKI(t)
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})
	chain := writeFile(t, "tunnel.pem", append(append(pemChain(pki.leaf), key...), pemChain(pki.ca)...))
	cfg := validConfig()
	cfg.CertificateFile = chain
	cfg.Token.Slot = 3
	cfg.Token.PINFile = writeFile(t, "token.pin", []byte("1234\r\nignored\n"))

	f, err := NewFileIdentity(cfg)
	if err != nil {
		t.Fatalf("NewFileIdentity: %v", err)
	}
	t.Cleanup(f.Close)
	id, err := f.TunnelIdentity(context.Background())
	if err != nil {
		t.Fatalf("TunnelIdentity: %v", err)
	}
	if len(id.Chain) != 2 || !id.Chain[0].Equal(pki.leaf) || !id.Chain[1].Equal(pki.ca) {
		t.Fatalf("chain of %d, want the leaf then the CA, other blocks skipped", len(id.Chain))
	}
	if id.Token.Slot != 3 || string(id.Token.KeyID) != "ipsec" || id.Token.Module != "" {
		t.Fatalf("token = %+v", id.Token)
	}
	buf, err := id.PIN.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer buf.Destroy()
	if !bytes.Equal(buf.Bytes(), []byte("1234")) {
		t.Fatal("the PIN is not the first line of the file")
	}

	// A renewed certificate on disk is read by the next call.
	if err := os.WriteFile(chain, pemChain(pki.ca), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if id, err := f.TunnelIdentity(context.Background()); err != nil || !id.Chain[0].Equal(pki.ca) {
		t.Fatalf("TunnelIdentity after renewal = %v, %v", id, err)
	}
}

func TestFileIdentityWithoutPIN(t *testing.T) {
	cfg := validConfig()
	cfg.CertificateFile = writeFile(t, "tunnel.pem", pemChain(newTestPKI(t).leaf))
	f, err := NewFileIdentity(cfg)
	if err != nil {
		t.Fatalf("NewFileIdentity: %v", err)
	}
	t.Cleanup(f.Close)
	if id, err := f.TunnelIdentity(context.Background()); err != nil || id.PIN != nil {
		t.Fatalf("TunnelIdentity = %+v, %v; want no PIN", id, err)
	}
}

func TestNewFileIdentityRejects(t *testing.T) {
	chain := writeFile(t, "tunnel.pem", pemChain(newTestPKI(t).leaf))
	tests := []struct {
		name   string
		mutate func(c *Config)
		field  string
		want   error
	}{
		{"no certificate file", func(c *Config) { c.CertificateFile = "" }, "certificate-file", ErrRequired},
		{"handle not hex", func(c *Config) { c.Token.Handle = "zz" }, "token.handle", ErrInvalidHandle},
		{"missing PIN file", func(c *Config) { c.Token.PINFile = filepath.Join(t.TempDir(), "absent") }, "token.pin-file", fs.ErrNotExist},
		{"empty PIN", func(c *Config) { c.Token.PINFile = writeFile(t, "token.pin", []byte("\nsecond line\n")) }, "token.pin-file", ErrRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.CertificateFile = chain
			tt.mutate(cfg)
			_, err := NewFileIdentity(cfg)
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) || cfgErr.Field != tt.field || !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v on %q", err, tt.want, tt.field)
			}
		})
	}
	if _, err := NewFileIdentity(&Config{}); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("disabled section: err = %v", err)
	}
}

func TestReadChainRejects(t *testing.T) {
	tests := []struct {
		name string
		path string
		want error
	}{
		{"missing", filepath.Join(t.TempDir(), "absent"), fs.ErrNotExist},
		{"no certificates", writeFile(t, "empty.pem", []byte("not pem")), ErrNoCertificate},
	}
	for _, tt := range tests {
		if _, err := readChain(tt.path); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
	garbage := writeFile(t, "bad.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
	var cfgErr *ConfigError
	if _, err := readChain(garbage); !errors.As(err, &cfgErr) || cfgErr.Field != "certificate-file" {
		t.Fatalf("unparsable certificate: err = %v", err)
	}
}
