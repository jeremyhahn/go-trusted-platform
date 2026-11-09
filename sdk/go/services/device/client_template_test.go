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

package device

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeTemplateServiceClient records the template requests the client
// sends and answers with canned replies.
type fakeTemplateServiceClient struct {
	platformv1.DeviceServiceClient

	createReq  *platformv1.DeviceTemplateCreateRequest
	createResp *platformv1.DeviceTemplateCreateResponse
	createErr  error
	fromReq    *platformv1.CreateProfileFromTemplateRequest
	fromResp   *platformv1.CreateProfileResponse
	fromErr    error
}

func (f *fakeTemplateServiceClient) CreateTemplate(_ context.Context, req *platformv1.DeviceTemplateCreateRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateCreateResponse, error) {
	f.createReq = req
	return f.createResp, f.createErr
}

func (f *fakeTemplateServiceClient) CreateProfileFromTemplate(_ context.Context, req *platformv1.CreateProfileFromTemplateRequest, _ ...grpc.CallOption) (*platformv1.CreateProfileResponse, error) {
	f.fromReq = req
	return f.fromResp, f.fromErr
}

func TestClient_CreateTemplate(t *testing.T) {
	fake := &fakeTemplateServiceClient{
		createResp: &platformv1.DeviceTemplateCreateResponse{
			Template: &platformv1.DeviceTemplate{Id: 9000, Name: "edge"},
		},
	}
	client := NewClientFromGRPC(fake)

	template, err := client.CreateTemplate(context.Background(), &platformv1.DeviceTemplate{
		Name: "edge",
		Role: platformv1.DeviceRole_DEVICE_ROLE_EDGE,
	})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if template.GetId() != 9000 {
		t.Errorf("template = %+v, want id 9000", template)
	}
	sent := fake.createReq.GetTemplate()
	if sent.GetName() != "edge" || sent.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_EDGE {
		t.Errorf("request template = %+v, fields not mapped", sent)
	}
}

func TestClient_CreateTemplate_Error(t *testing.T) {
	cause := errors.New("boom")
	client := NewClientFromGRPC(&fakeTemplateServiceClient{createErr: cause})

	_, err := client.CreateTemplate(context.Background(), &platformv1.DeviceTemplate{Name: "edge"})
	var typed *ErrCreateTemplateFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want ErrCreateTemplateFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("cause lost: %v", err)
	}
}

func TestClient_CreateProfileFromTemplate(t *testing.T) {
	fake := &fakeTemplateServiceClient{
		fromResp: &platformv1.CreateProfileResponse{
			Profile: &platformv1.DeviceProfile{Id: 77, Name: "edge-01"},
		},
	}
	client := NewClientFromGRPC(fake)

	profile, err := client.CreateProfileFromTemplate(context.Background(), 9000,
		&platformv1.DeviceProfile{Name: "edge-01", EkSerial: "EK-1"})
	if err != nil {
		t.Fatalf("CreateProfileFromTemplate: %v", err)
	}
	if profile.GetId() != 77 {
		t.Errorf("profile = %+v, want id 77", profile)
	}
	req := fake.fromReq
	if req.GetTemplateId() != 9000 || req.GetOverrides().GetEkSerial() != "EK-1" {
		t.Errorf("request = %+v, fields not mapped", req)
	}
}

func TestClient_CreateProfileFromTemplate_Error(t *testing.T) {
	cause := errors.New("template not found")
	client := NewClientFromGRPC(&fakeTemplateServiceClient{fromErr: cause})

	_, err := client.CreateProfileFromTemplate(context.Background(), 4242, nil)
	var typed *ErrCreateProfileFromTemplateFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want ErrCreateProfileFromTemplateFailed", err)
	}
	if typed.TemplateID != 4242 || !errors.Is(err, cause) {
		t.Errorf("typed = %+v, template id or cause lost", typed)
	}
}
