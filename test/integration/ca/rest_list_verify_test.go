//go:build integration

package ca

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestRESTAdapterListCertificatesDecodesProtoResponse checks that the
// adapter decodes the webservice's protobuf JSON list response, whose
// timestamp is an RFC3339 string and whose total sits in a nested
// pagination message.
func TestRESTAdapterListCertificatesDecodesProtoResponse(t *testing.T) {
	payload, err := protojson.Marshal(&pb.ListCertificatesResponse{
		Certificates: []*pb.CertificateSummary{
			{Serial: "01", CommonName: "a.example.com", Issuer: "root-ca.example.com"},
			{Serial: "02", CommonName: "b.example.com", Issuer: "root-ca.example.com"},
		},
		Pagination: &pb.PaginationResponse{Page: 1, PageSize: 2, TotalPages: 2, TotalItems: 3},
		Timestamp:  timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("marshal ListCertificatesResponse: %v", err)
	}

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/api/v1/ca/certificates" {
			http.NotFound(w, req)
			return
		}
		gotQuery = req.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":200,"success":true,"payload":%s}`, payload)
	}))
	defer srv.Close()

	adapter := &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := adapter.ListCertificates(context.Background(), ListCertificatesOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if gotQuery != "page_size=2" {
		t.Errorf("query = %q, want page_size=2", gotQuery)
	}
	if len(result.Certificates) != 2 || result.Certificates[0].Serial != "01" ||
		result.Certificates[1].CommonName != "b.example.com" {
		t.Errorf("Certificates = %+v, want serials 01 and 02", result.Certificates)
	}
	if result.Total != 3 {
		t.Errorf("Total = %d, want 3", result.Total)
	}
}

// TestRESTAdapterVerifyCertificateSendsProtoRequest checks that the adapter
// sends a protobuf JSON VerifyCertificateRequest (certificate_pem as base64
// bytes) and decodes the protobuf VerifyCertificateResponse.
func TestRESTAdapterVerifyCertificateSendsProtoRequest(t *testing.T) {
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

	payload, err := protojson.Marshal(&pb.VerifyCertificateResponse{
		Status:    &pb.Status{Success: true, Message: "verified"},
		Valid:     true,
		Chain:     []string{"leaf.example.com", "root-ca.example.com"},
		Warnings:  []string{"expires soon"},
		Timestamp: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("marshal VerifyCertificateResponse: %v", err)
	}

	var got pb.VerifyCertificateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/api/v1/ca/certificates/verify" {
			http.NotFound(w, req)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := protojson.Unmarshal(body, &got); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"code":400,"success":false,"error":%q}`, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":200,"success":true,"payload":%s}`, payload)
	}))
	defer srv.Close()

	adapter := &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := adapter.VerifyCertificate(context.Background(), VerifyCertificateOptions{
		CertificatePEM:  certPEM,
		CheckExpiration: true,
		CheckCRL:        true,
	})
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if string(got.CertificatePem) != string(certPEM) {
		t.Errorf("request certificate_pem = %q, want %q", got.CertificatePem, certPEM)
	}
	if !got.VerifyExpiration || !got.VerifyRevocation {
		t.Errorf("request flags expiration=%v revocation=%v, want both true",
			got.VerifyExpiration, got.VerifyRevocation)
	}
	if !result.Valid || !result.ChainValid || result.Revoked {
		t.Errorf("result = %+v, want valid, chain valid, not revoked", result)
	}
	if result.ChainLength != 2 || len(result.Warnings) != 1 {
		t.Errorf("chain length %d warnings %v, want 2 and one warning", result.ChainLength, result.Warnings)
	}
	if result.ValidationError != "" {
		t.Errorf("ValidationError = %q, want empty", result.ValidationError)
	}
}
