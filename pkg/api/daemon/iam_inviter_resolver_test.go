package daemon

import (
	"context"
	"errors"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// fakeInviterIAMClient answers only GetUserByEmail; every other IAMClient
// method panics through the nil embedded interface.
type fakeInviterIAMClient struct {
	restiam.IAMClient
	user     *iamsdk.User
	err      error
	tenantID string
	email    string
}

func (f *fakeInviterIAMClient) GetUserByEmail(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
	f.tenantID = tenantID
	f.email = email
	return f.user, f.err
}

func TestIAMInviterResolver_ResolvesIAMUser(t *testing.T) {
	client := &fakeInviterIAMClient{user: &iamsdk.User{ID: "42", Email: "admin@example.com"}}
	user, err := newIAMInviterResolver(client, "system").GetByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if user == nil || user.ID != 42 || user.Email != "admin@example.com" {
		t.Fatalf("got %+v, want id 42 admin@example.com", user)
	}
	if client.tenantID != "system" || client.email != "admin@example.com" {
		t.Fatalf("lookup used tenant %q email %q", client.tenantID, client.email)
	}
}

func TestIAMInviterResolver_NotFoundIsUserNotFound(t *testing.T) {
	client := &fakeInviterIAMClient{err: sdkerrors.NewNotFound("iam.GetUserByEmail", "x")}
	_, err := newIAMInviterResolver(client, "system").GetByEmail(context.Background(), "nobody@example.com")
	var notFound platformservice.ErrUserNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("got %v, want ErrUserNotFound", err)
	}
	if notFound.Email != "nobody@example.com" {
		t.Fatalf("ErrUserNotFound email %q", notFound.Email)
	}
}

func TestIAMInviterResolver_NonDecimalIDIsNotUsable(t *testing.T) {
	for _, id := range []string{"usr-abc", "0", ""} {
		client := &fakeInviterIAMClient{user: &iamsdk.User{ID: id, Email: "admin@example.com"}}
		_, err := newIAMInviterResolver(client, "system").GetByEmail(context.Background(), "admin@example.com")
		var unusable ErrInviterIDNotUsable
		if !errors.As(err, &unusable) {
			t.Fatalf("id %q: got %v, want ErrInviterIDNotUsable", id, err)
		}
		if unusable.ID != id {
			t.Fatalf("id %q: error names %q", id, unusable.ID)
		}
	}
}

func TestIAMInviterResolver_OtherErrorIsWrapped(t *testing.T) {
	cause := sdkerrors.NewUnavailable("iam.GetUserByEmail", "down")
	client := &fakeInviterIAMClient{err: cause}
	_, err := newIAMInviterResolver(client, "system").GetByEmail(context.Background(), "admin@example.com")
	if err == nil || !errors.Is(err, cause) {
		t.Fatalf("got %v, want a wrap of %v", err, cause)
	}
	var notFound platformservice.ErrUserNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("an IAM outage was reported as not found: %v", err)
	}
}
