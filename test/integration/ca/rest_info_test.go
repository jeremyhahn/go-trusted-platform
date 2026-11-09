//go:build integration

package ca

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestRESTAdapterInfoDecodesGetCAInfoResponse serves the protojson
// GetCAInfoResponse the webservice CA handler writes, inside the webservice
// envelope, and checks the REST adapter maps every CaInfo field.
func TestRESTAdapterInfoDecodesGetCAInfoResponse(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(10, 0, 0)

	payload, err := protojson.Marshal(&pb.GetCAInfoResponse{
		CaInfo: &pb.CAInfo{
			CommonName:     "root-ca.example.com",
			IsInitialized:  true,
			IsIntermediate: true,
			RootCert: &pb.CertificateSummary{
				Serial:     "0a1b2c",
				CommonName: "root-ca.example.com",
				Issuer:     "root-ca.example.com",
				NotBefore:  timestamppb.New(notBefore),
				NotAfter:   timestamppb.New(notAfter),
			},
			Intermediates: []*pb.CertificateSummary{{
				Serial:     "3d4e5f",
				CommonName: "intermediate-ca.example.com",
				Issuer:     "root-ca.example.com",
			}},
			KeyStores: []*pb.KeyStoreInfo{{
				Type:         "pkcs8",
				Available:    true,
				Capabilities: []string{"sign"},
			}},
			DefaultAlgorithm:    "ECDSA",
			DefaultValidityDays: 365,
		},
		Timestamp: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("marshal GetCAInfoResponse: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/api/v1/ca/info" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":200,"success":true,"payload":%s}`, payload)
	}))
	defer srv.Close()

	adapter := &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}
	info, err := adapter.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if info.CommonName != "root-ca.example.com" {
		t.Errorf("CommonName = %q, want root-ca.example.com", info.CommonName)
	}
	if !info.IsInitialized {
		t.Errorf("IsInitialized = false, want true")
	}
	if !info.IsIntermediate {
		t.Errorf("IsIntermediate = false, want true")
	}
	if info.DefaultAlgorithm != "ECDSA" {
		t.Errorf("DefaultAlgorithm = %q, want ECDSA", info.DefaultAlgorithm)
	}
	if info.DefaultValidityDays != 365 {
		t.Errorf("DefaultValidityDays = %d, want 365", info.DefaultValidityDays)
	}
	if info.RootCertificate == nil {
		t.Fatalf("RootCertificate = nil, want the root summary")
	}
	if info.RootCertificate.Serial != "0a1b2c" || info.RootCertificate.CommonName != "root-ca.example.com" {
		t.Errorf("RootCertificate = %+v, want serial 0a1b2c and CN root-ca.example.com", info.RootCertificate)
	}
	if !info.RootCertificate.NotBefore.Equal(notBefore) || !info.RootCertificate.NotAfter.Equal(notAfter) {
		t.Errorf("RootCertificate validity = %v..%v, want %v..%v",
			info.RootCertificate.NotBefore, info.RootCertificate.NotAfter, notBefore, notAfter)
	}
	if len(info.Intermediates) != 1 || info.Intermediates[0].Serial != "3d4e5f" ||
		info.Intermediates[0].CommonName != "intermediate-ca.example.com" {
		t.Errorf("Intermediates = %+v, want one with serial 3d4e5f", info.Intermediates)
	}
	if len(info.KeyStores) != 1 || info.KeyStores[0].Type != "pkcs8" || !info.KeyStores[0].Available ||
		len(info.KeyStores[0].Capabilities) != 1 || info.KeyStores[0].Capabilities[0] != "sign" {
		t.Errorf("KeyStores = %+v, want one available pkcs8 store with sign", info.KeyStores)
	}
}
