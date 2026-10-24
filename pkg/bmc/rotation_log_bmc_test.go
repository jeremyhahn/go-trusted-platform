package bmc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// loggedEngine builds a rotation engine whose logger writes to buf.
func loggedEngine(t *testing.T, store CredentialStore, sf *stageFactory, buf *bytes.Buffer) *RotationEngine {
	t.Helper()
	e, err := NewRotationEngine(RotationOptions{
		Store:   store,
		Factory: sf.factory(),
		Generate: func() (*memguard.MemoryEnclave, error) {
			return memguard.NewMemoryEnclave([]byte("NEW_PW")), nil
		},
		Logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("NewRotationEngine: %v", err)
	}
	return e
}

func rotationStore(t *testing.T) *MemoryStore {
	t.Helper()
	store := NewMemoryStore()
	t.Cleanup(store.DestroyAll)
	if err := store.Put(context.Background(), "bmc01", NewCredentials("ADMIN", []byte("OLD_PW"))); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	return store
}

func TestRotationEngine_LogsVerifiedRotation(t *testing.T) {
	var buf bytes.Buffer
	sf := &stageFactory{}
	sf.add(&fakeUM{}, nil)
	sf.add(&fakeUM{}, nil)
	e := loggedEngine(t, rotationStore(t), sf, &buf)

	cfg := &Config{Address: "x", Port: 623, Protocol: ProtocolIPMI}
	if err := e.RotateOnce(context.Background(), "bmc01", cfg, 2); err != nil {
		t.Fatalf("RotateOnce: %v", err)
	}
	logged := buf.String()
	for _, want := range []string{"bmc: rotation: new password stored", "bmc: rotation: verified", "name=bmc01", "slot=2"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q does not contain %q", logged, want)
		}
	}
	if strings.Contains(logged, "NEW_PW") || strings.Contains(logged, "OLD_PW") {
		t.Errorf("log %q leaks a password", logged)
	}
}

func TestRotationEngine_LogsRollback(t *testing.T) {
	var buf bytes.Buffer
	sf := &stageFactory{}
	sf.add(&fakeUM{}, nil)
	sf.add(&fakeUM{maxUsersErr: errors.New("auth denied with new pw")}, nil)
	sf.add(&fakeUM{}, nil)
	e := loggedEngine(t, rotationStore(t), sf, &buf)

	cfg := &Config{Address: "x", Port: 623, Protocol: ProtocolIPMI}
	var reverted ErrRotationReverted
	if err := e.RotateOnce(context.Background(), "bmc01", cfg, 2); !errors.As(err, &reverted) {
		t.Fatalf("RotateOnce error = %v, want ErrRotationReverted", err)
	}
	logged := buf.String()
	if !strings.Contains(logged, "bmc: rotation: apply or verify failed, attempting rollback") ||
		!strings.Contains(logged, "auth denied with new pw") {
		t.Errorf("log %q does not record the rollback and its cause", logged)
	}
	if strings.Contains(logged, "rotation: verified") {
		t.Errorf("log %q claims a verified rotation", logged)
	}
}
