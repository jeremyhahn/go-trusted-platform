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

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestTPMKeysMethodsAreRouted(t *testing.T) {
	want := map[string]string{
		platformv1.TPMService_Provision_FullMethodName:           "platform_tpm_provision",
		platformv1.TPMService_Clear_FullMethodName:               "platform_tpm_clear",
		platformv1.TPMService_CreateEK_FullMethodName:            "platform_tpm_ek_create",
		platformv1.TPMService_DeleteEK_FullMethodName:            "platform_tpm_ek_delete",
		platformv1.TPMService_ImportEKCertificate_FullMethodName: "platform_tpm_ek_import_cert",
		platformv1.TPMService_CreateSRK_FullMethodName:           "platform_tpm_srk_create",
		platformv1.TPMService_DeleteSRK_FullMethodName:           "platform_tpm_srk_delete",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
	}
}

// tpmKeysInvoke calls method on a fresh test server whose tool answers
// result, and returns the calls the server saw and the Invoke error.
func tpmKeysInvoke(t *testing.T, tool string, result interface{}, method string, in, reply proto.Message) ([]toolCall, error) {
	t.Helper()
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{tool: result}, &calls)
	err := adapter.Connection().Invoke(context.Background(), method, in, reply)
	return calls, err
}

// tpmKeysExpectRefused checks that Invoke answers InvalidArgument and that no
// tool call went out.
func tpmKeysExpectRefused(t *testing.T, name, tool, method string, in, reply proto.Message) {
	t.Helper()
	calls, err := tpmKeysInvoke(t, tool, map[string]interface{}{"success": true}, method, in, reply)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("%s: Invoke code = %v (%v), want InvalidArgument", name, status.Code(err), err)
	}
	if len(calls) != 0 {
		t.Errorf("%s: calls = %v, want none", name, calls)
	}
}

// tpmKeysExpectOneCall checks one call to tool with the given arguments.
func tpmKeysExpectOneCall(t *testing.T, calls []toolCall, err error, tool string, want map[string]interface{}) {
	t.Helper()
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != tool {
		t.Fatalf("calls = %v, want one %s call", calls, tool)
	}
	got := calls[0].Arguments
	if got == nil {
		got = map[string]interface{}{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wire args = %v, want %v", got, want)
	}
}

func tpmKeysCheckStatus(t *testing.T, st *platformv1.Status, message string) {
	t.Helper()
	if !st.GetSuccess() || st.GetMessage() != message {
		t.Errorf("status = %v, want success %q", st, message)
	}
}

func TestInvoke_TPMProvision_SendsTheOwnerAuth(t *testing.T) {
	const tool, method = "platform_tpm_provision", platformv1.TPMService_Provision_FullMethodName
	// The test server is plaintext http://, so the call goes without a
	// password; the owner_password wire argument is checked on the builder.
	reply := &platformv1.TPMProvisionResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "TPM provisioned successfully"},
		method, &platformv1.TPMProvisionRequest{CreateEk: true, CreateSrk: true}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{})
	tpmKeysCheckStatus(t, reply.GetStatus(), "TPM provisioned successfully")

	got, err := buildTPMKeysProvisionArgs(&platformv1.TPMProvisionRequest{OwnerPassword: "owner", CreateEk: true, CreateSrk: true})
	if err != nil {
		t.Fatalf("buildTPMKeysProvisionArgs: %v", err)
	}
	if want := map[string]interface{}{"owner_password": "owner"}; !reflect.DeepEqual(got, want) {
		t.Errorf("provision args = %v, want %v", got, want)
	}

	tpmKeysExpectRefused(t, "endorsement password", tool, method,
		&platformv1.TPMProvisionRequest{CreateEk: true, CreateSrk: true, EndorsementPassword: "e"}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectRefused(t, "ek attributes", tool, method,
		&platformv1.TPMProvisionRequest{CreateEk: true, CreateSrk: true, EkAttributes: &platformv1.KeyAttributes{}}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectRefused(t, "create ak", tool, method,
		&platformv1.TPMProvisionRequest{CreateEk: true, CreateSrk: true, CreateAk: true}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectRefused(t, "no srk", tool, method,
		&platformv1.TPMProvisionRequest{CreateEk: true}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectRefused(t, "no ek", tool, method,
		&platformv1.TPMProvisionRequest{CreateSrk: true}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectRefused(t, "neither key", tool, method,
		&platformv1.TPMProvisionRequest{}, &platformv1.TPMProvisionResponse{})
}

func TestInvoke_TPMClear_NeedsConfirm(t *testing.T) {
	const tool, method = "platform_tpm_clear", platformv1.TPMService_Clear_FullMethodName
	tpmKeysExpectRefused(t, "zero value", tool, method,
		&platformv1.TPMClearRequest{}, &platformv1.TPMClearResponse{})

	reply := &platformv1.TPMClearResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "TPM cleared"},
		method, &platformv1.TPMClearRequest{Confirm: true}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{})
	tpmKeysCheckStatus(t, reply.GetStatus(), "TPM cleared")

	got, err := buildTPMKeysClearArgs(&platformv1.TPMClearRequest{Confirm: true, OwnerPassword: "owner"})
	if err != nil {
		t.Fatalf("buildTPMKeysClearArgs: %v", err)
	}
	if want := map[string]interface{}{"owner_password": "owner"}; !reflect.DeepEqual(got, want) {
		t.Errorf("clear args = %v, want %v", got, want)
	}
}

func TestInvoke_TPMCreateEK_CarriesTheHandle(t *testing.T) {
	const tool, method = "platform_tpm_ek_create", platformv1.TPMService_CreateEK_FullMethodName
	reply := &platformv1.CreateEKResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "EK created", "handle": 0x81010001},
		method, &platformv1.CreateEKRequest{Persistent: true}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{})
	tpmKeysCheckStatus(t, reply.GetStatus(), "EK created")
	if reply.GetHandle() != 0x81010001 {
		t.Errorf("handle = %#x, want 0x81010001", reply.GetHandle())
	}

	tpmKeysExpectRefused(t, "attributes", tool, method,
		&platformv1.CreateEKRequest{Persistent: true, Attributes: &platformv1.KeyAttributes{}}, &platformv1.CreateEKResponse{})
	tpmKeysExpectRefused(t, "transient", tool, method,
		&platformv1.CreateEKRequest{}, &platformv1.CreateEKResponse{})
}

func TestInvoke_TPMCreateSRK_CarriesTheHandle(t *testing.T) {
	const tool, method = "platform_tpm_srk_create", platformv1.TPMService_CreateSRK_FullMethodName
	reply := &platformv1.CreateSRKResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "SRK created", "handle": 0x81000001},
		method, &platformv1.CreateSRKRequest{Persistent: true}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{})
	tpmKeysCheckStatus(t, reply.GetStatus(), "SRK created")
	if reply.GetHandle() != 0x81000001 {
		t.Errorf("handle = %#x, want 0x81000001", reply.GetHandle())
	}

	tpmKeysExpectRefused(t, "attributes", tool, method,
		&platformv1.CreateSRKRequest{Persistent: true, Attributes: &platformv1.KeyAttributes{}}, &platformv1.CreateSRKResponse{})
	tpmKeysExpectRefused(t, "parent handle", tool, method,
		&platformv1.CreateSRKRequest{Persistent: true, ParentHandle: 1}, &platformv1.CreateSRKResponse{})
	tpmKeysExpectRefused(t, "parent password", tool, method,
		&platformv1.CreateSRKRequest{Persistent: true, ParentPassword: "p"}, &platformv1.CreateSRKResponse{})
	tpmKeysExpectRefused(t, "transient", tool, method,
		&platformv1.CreateSRKRequest{}, &platformv1.CreateSRKResponse{})
}

func TestInvoke_TPMDeleteEK_SendsTheHandle(t *testing.T) {
	const tool, method = "platform_tpm_ek_delete", platformv1.TPMService_DeleteEK_FullMethodName
	reply := &platformv1.DeleteEKResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "EK deleted"},
		method, &platformv1.DeleteEKRequest{Handle: 0x81010001}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{"handle": float64(0x81010001)})
	tpmKeysCheckStatus(t, reply.GetStatus(), "EK deleted")

	tpmKeysExpectRefused(t, "algorithm", tool, method,
		&platformv1.DeleteEKRequest{Handle: 0x81010001, Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		&platformv1.DeleteEKResponse{})
	tpmKeysExpectRefused(t, "password", tool, method,
		&platformv1.DeleteEKRequest{Handle: 0x81010001, Password: "x"}, &platformv1.DeleteEKResponse{})
}

func TestInvoke_TPMDeleteSRK_SendsTheHandle(t *testing.T) {
	const tool, method = "platform_tpm_srk_delete", platformv1.TPMService_DeleteSRK_FullMethodName
	reply := &platformv1.DeleteSRKResponse{}
	calls, err := tpmKeysInvoke(t, tool,
		map[string]interface{}{"success": true, "message": "SRK deleted"},
		method, &platformv1.DeleteSRKRequest{Handle: 0x81010001}, reply)
	tpmKeysExpectOneCall(t, calls, err, tool, map[string]interface{}{"handle": float64(0x81010001)})
	tpmKeysCheckStatus(t, reply.GetStatus(), "SRK deleted")

	tpmKeysExpectRefused(t, "algorithm", tool, method,
		&platformv1.DeleteSRKRequest{Handle: 0x81010001, Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		&platformv1.DeleteSRKResponse{})
	tpmKeysExpectRefused(t, "password", tool, method,
		&platformv1.DeleteSRKRequest{Handle: 0x81010001, Password: "x"}, &platformv1.DeleteSRKResponse{})
}

// tpmKeysTestCertificate builds a throwaway self-signed certificate in memory.
func tpmKeysTestCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test EK"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(0, 0).Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestInvoke_TPMImportEKCertificate_PEMAndDER(t *testing.T) {
	const tool, method = "platform_tpm_ek_import_cert", platformv1.TPMService_ImportEKCertificate_FullMethodName
	der := tpmKeysTestCertificate(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	want := map[string]interface{}{"certificate": base64.StdEncoding.EncodeToString(der)}

	for _, tc := range []struct {
		name string
		in   *platformv1.ImportEKCertificateRequest
	}{
		{"DER", &platformv1.ImportEKCertificateRequest{Certificate: der, Format: "DER"}},
		{"pem", &platformv1.ImportEKCertificateRequest{Certificate: pemBytes, Format: "pem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := &platformv1.ImportEKCertificateResponse{}
			calls, err := tpmKeysInvoke(t, tool,
				map[string]interface{}{"success": true, "message": "EK certificate imported"},
				method, tc.in, reply)
			tpmKeysExpectOneCall(t, calls, err, tool, want)
			tpmKeysCheckStatus(t, reply.GetStatus(), "EK certificate imported")
		})
	}

	tpmKeysExpectRefused(t, "TXT", tool, method,
		&platformv1.ImportEKCertificateRequest{Certificate: der, Format: "TXT"}, &platformv1.ImportEKCertificateResponse{})
	tpmKeysExpectRefused(t, "nvram index", tool, method,
		&platformv1.ImportEKCertificateRequest{Certificate: der, Format: "DER", NvramIndex: 0x01C00002},
		&platformv1.ImportEKCertificateResponse{})
	tpmKeysExpectRefused(t, "PEM without a block", tool, method,
		&platformv1.ImportEKCertificateRequest{Certificate: []byte("not pem"), Format: "PEM"},
		&platformv1.ImportEKCertificateResponse{})
	tpmKeysExpectRefused(t, "malformed DER", tool, method,
		&platformv1.ImportEKCertificateRequest{Certificate: []byte("not a certificate"), Format: "DER"},
		&platformv1.ImportEKCertificateResponse{})
	tpmKeysExpectRefused(t, "malformed PEM", tool, method,
		&platformv1.ImportEKCertificateRequest{
			Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
			Format:      "PEM",
		},
		&platformv1.ImportEKCertificateResponse{})
}

func TestTPMKeysDecoders_RejectWrongTypes(t *testing.T) {
	builders := map[string]func(interface{}) (map[string]interface{}, error){
		"provision": buildTPMKeysProvisionArgs,
		"clear":     buildTPMKeysClearArgs,
		"createEK":  buildTPMKeysCreateEKArgs,
		"deleteEK":  buildTPMKeysDeleteEKArgs,
		"importEK":  buildTPMKeysImportEKCertificateArgs,
		"createSRK": buildTPMKeysCreateSRKArgs,
		"deleteSRK": buildTPMKeysDeleteSRKArgs,
	}
	for name, build := range builders {
		var wrongArgs ErrUnexpectedArgsType
		if _, err := build(&platformv1.QuoteRequest{}); !errors.As(err, &wrongArgs) {
			t.Errorf("%s args: got %v, want ErrUnexpectedArgsType", name, err)
		}
	}
	decoders := map[string]func(interface{}, interface{}) error{
		"provision": decodeTPMKeysProvisionResult,
		"clear":     decodeTPMKeysClearResult,
		"createEK":  decodeTPMKeysCreateEKResult,
		"deleteEK":  decodeTPMKeysDeleteEKResult,
		"importEK":  decodeTPMKeysImportEKCertificateResult,
		"createSRK": decodeTPMKeysCreateSRKResult,
		"deleteSRK": decodeTPMKeysDeleteSRKResult,
	}
	for name, decode := range decoders {
		var wrongReply ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{"success": true}, &platformv1.QuoteResponse{}); !errors.As(err, &wrongReply) {
			t.Errorf("%s reply: got %v, want ErrUnexpectedReplyType", name, err)
		}
	}
}

// TestInvoke_TPMKeys_RefuseAPasswordOverPlaintext: the test server is
// plaintext http://, so a request carrying an owner password is refused
// with FailedPrecondition and no call goes out.
func TestInvoke_TPMKeys_RefuseAPasswordOverPlaintext(t *testing.T) {
	cases := []struct {
		name, tool, method string
		in, reply          proto.Message
	}{
		{"provision", "platform_tpm_provision", platformv1.TPMService_Provision_FullMethodName,
			&platformv1.TPMProvisionRequest{OwnerPassword: "owner", CreateEk: true, CreateSrk: true}, &platformv1.TPMProvisionResponse{}},
		{"clear", "platform_tpm_clear", platformv1.TPMService_Clear_FullMethodName,
			&platformv1.TPMClearRequest{OwnerPassword: "owner", Confirm: true}, &platformv1.TPMClearResponse{}},
	}
	for _, tc := range cases {
		calls, err := tpmKeysInvoke(t, tc.tool, map[string]interface{}{"success": true}, tc.method, tc.in, tc.reply)
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: Invoke code = %v (%v), want FailedPrecondition", tc.name, status.Code(err), err)
		}
		if len(calls) != 0 {
			t.Errorf("%s: calls = %v, want none", tc.name, calls)
		}
	}
}

// TestInvoke_TPMKeys_NoPasswordGoesOverPlaintext: the same requests without
// a password still reach the plaintext test server.
func TestInvoke_TPMKeys_NoPasswordGoesOverPlaintext(t *testing.T) {
	calls, err := tpmKeysInvoke(t, "platform_tpm_provision", map[string]interface{}{"success": true},
		platformv1.TPMService_Provision_FullMethodName,
		&platformv1.TPMProvisionRequest{CreateEk: true, CreateSrk: true}, &platformv1.TPMProvisionResponse{})
	tpmKeysExpectOneCall(t, calls, err, "platform_tpm_provision", map[string]interface{}{})

	calls, err = tpmKeysInvoke(t, "platform_tpm_clear", map[string]interface{}{"success": true},
		platformv1.TPMService_Clear_FullMethodName,
		&platformv1.TPMClearRequest{Confirm: true}, &platformv1.TPMClearResponse{})
	tpmKeysExpectOneCall(t, calls, err, "platform_tpm_clear", map[string]interface{}{})
}
