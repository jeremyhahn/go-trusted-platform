// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeWebserviceCA satisfies the CA surface that buildWebServiceCertTarget
// touches. The interface is embedded (nil) so that any method OTHER than the
// two overridden below panics loudly rather than passing silently — if the
// builder grows a new CA dependency, these tests fail instead of drifting.
type fakeWebserviceCA struct {
	quicbaasca.CACertificateAuthority
	rootErr error
	poolErr error
}

func (f *fakeWebserviceCA) TrustedRoot() (*x509.Certificate, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	return &x509.Certificate{}, nil
}

func (f *fakeWebserviceCA) TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error) {
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	return x509.NewCertPool(), nil
}

func newWebserviceCertApp(ca quicbaasca.CACertificateAuthority) *App {
	return &App{
		Logger:                  logging.DefaultLogger(),
		CA:                      ca,
		WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{},
	}
}

// The defect behind issue #31's review: on an ordinary restart the CA already
// holds the certificate, so InitWebServer jumps straight to certLoaded and
// never calls issueWebServiceCertificate — which was the only code that
// registered a renewal target. The sweep then had nothing to renew and the
// certificate silently ran to expiry.

func TestRegisterWebServiceCertTarget_RegistersARenewableTarget(t *testing.T) {
	a := newWebserviceCertApp(&fakeWebserviceCA{})

	a.registerWebServiceCertTarget(context.Background(), "api",
		&v1.Config{TLSPort: 8443}, &xkmssdk.KeyAttributes{CN: "api.example.com"})

	target, ok := a.certTargets().Get("webservice.api")
	if !ok {
		t.Fatal("no renewal target was registered, so the daily sweep would find " +
			"nothing and the certificate would run to expiry")
	}
	if target.Kind != CertKindWebservice {
		t.Errorf("Kind = %v, want %v", target.Kind, CertKindWebservice)
	}
	if target.Current == nil {
		t.Error("target has no Current func: the sweep cannot read the live " +
			"certificate, so it can never decide to renew")
	}
	if target.Reissue == nil {
		t.Error("target has no Reissue func: the sweep could detect expiry but " +
			"would have no way to renew")
	}
}

func TestRegisterWebServiceCertTarget_IsIdempotent(t *testing.T) {
	// Reached on every boot AND on every renewal (the Reissue closure re-enters
	// issueWebServiceCertificate). A second registration must replace, not
	// duplicate, or two entries would race to renew the same certificate.
	a := newWebserviceCertApp(&fakeWebserviceCA{})
	ctx := context.Background()
	cfg := &v1.Config{TLSPort: 8443}
	attrs := &xkmssdk.KeyAttributes{CN: "api.example.com"}

	a.registerWebServiceCertTarget(ctx, "api", cfg, attrs)
	a.registerWebServiceCertTarget(ctx, "api", cfg, attrs)

	if n := a.certTargets().Len(); n != 1 {
		t.Errorf("registry holds %d targets after two registrations, want 1", n)
	}
}

func TestRegisterWebServiceCertTarget_DoesNotRegisterWhenTheCAFails(t *testing.T) {
	// A half-built target is worse than none: the sweep would keep dialling a
	// target it can never validate. Registration must be skipped, not partial,
	// and the failure must not take the caller down — the service still serves.
	for name, ca := range map[string]quicbaasca.CACertificateAuthority{
		"trusted root unavailable": &fakeWebserviceCA{rootErr: errors.New("no root")},
		"cert pool unavailable":    &fakeWebserviceCA{poolErr: errors.New("bad pool")},
	} {
		t.Run(name, func(t *testing.T) {
			a := newWebserviceCertApp(ca)

			a.registerWebServiceCertTarget(context.Background(), "api",
				&v1.Config{TLSPort: 8443}, &xkmssdk.KeyAttributes{CN: "api.example.com"})

			if n := a.certTargets().Len(); n != 0 {
				t.Errorf("registered %d targets despite the CA failing; a target "+
					"built on a failed CA cannot be validated by the sweep", n)
			}
		})
	}
}
