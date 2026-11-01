package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
)

// errCoverage964e is the cause the fakes and wrappers in this file return.
var errCoverage964e = errors.New("coverage 964e: injected failure")

// recordingKVClient is a KV client that records the last request of each
// kind and answers with the configured responses.
type recordingKVClient struct {
	quicbaassdk.KVClient
	err      error
	listResp *service.ListResponse

	put    *service.PutRequest
	delete *service.DeleteRequest
	list   *service.ListRequest
}

func (k *recordingKVClient) Put(_ context.Context, req *service.PutRequest) (*service.PutResponse, error) {
	k.put = req
	if k.err != nil {
		return nil, k.err
	}
	return &service.PutResponse{}, nil
}

func (k *recordingKVClient) Delete(_ context.Context, req *service.DeleteRequest) (*service.DeleteResponse, error) {
	k.delete = req
	if k.err != nil {
		return nil, k.err
	}
	return &service.DeleteResponse{}, nil
}

func (k *recordingKVClient) List(_ context.Context, req *service.ListRequest) (*service.ListResponse, error) {
	k.list = req
	if k.err != nil {
		return nil, k.err
	}
	return k.listResp, nil
}

func TestCoverage964e_SDKIPAMClientIsStarted(t *testing.T) {
	if (&sdkIPAMClient{}).IsStarted() {
		t.Fatal("IsStarted() = true without an SDK client")
	}
	if !(&sdkIPAMClient{sdk: &kvOnlyClient{}}).IsStarted() {
		t.Fatal("IsStarted() = false with an SDK client")
	}
}

func TestCoverage964e_SDKIPAMClientPut(t *testing.T) {
	kv := &recordingKVClient{}
	c := &sdkIPAMClient{sdk: &kvOnlyClient{kv: kv}}
	data := []byte(`{"id":"pool-a"}`)
	if err := c.Put(context.Background(), "ipam/pool", 9, data); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if kv.put == nil || kv.put.EntityType != "ipam/pool" || kv.put.ID != 9 || string(kv.put.Data) != string(data) {
		t.Fatalf("Put() sent %+v, want ipam/pool id 9 with the data", kv.put)
	}

	failing := &sdkIPAMClient{sdk: &kvOnlyClient{kv: &recordingKVClient{err: errCoverage964e}}}
	if err := failing.Put(context.Background(), "ipam/pool", 9, data); !errors.Is(err, errCoverage964e) {
		t.Fatalf("Put() error = %v, want the KV error", err)
	}
}

func TestCoverage964e_SDKIPAMClientDelete(t *testing.T) {
	kv := &recordingKVClient{}
	c := &sdkIPAMClient{sdk: &kvOnlyClient{kv: kv}}
	if err := c.Delete(context.Background(), "ipam/lease", 4); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if kv.delete == nil || kv.delete.EntityType != "ipam/lease" || kv.delete.ID != 4 {
		t.Fatalf("Delete() sent %+v, want ipam/lease id 4", kv.delete)
	}

	failing := &sdkIPAMClient{sdk: &kvOnlyClient{kv: &recordingKVClient{err: errCoverage964e}}}
	if err := failing.Delete(context.Background(), "ipam/lease", 4); !errors.Is(err, errCoverage964e) {
		t.Fatalf("Delete() error = %v, want the KV error", err)
	}
}

func TestCoverage964e_SDKIPAMClientList(t *testing.T) {
	entities := []*service.Entity{{ID: 1}, {ID: 2}}
	kv := &recordingKVClient{listResp: &service.ListResponse{Entities: entities, NextPageToken: "next"}}
	c := &sdkIPAMClient{sdk: &kvOnlyClient{kv: kv}}
	got, token, err := c.List(context.Background(), "ipam/pool", 50, "first")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 || token != "next" {
		t.Fatalf("List() = (%v, %q), want both entities and token next", got, token)
	}
	if kv.list.EntityType != "ipam/pool" || kv.list.PageSize != 50 || kv.list.PageToken != "first" {
		t.Fatalf("List() sent %+v, want ipam/pool page 50 from token first", kv.list)
	}

	failing := &sdkIPAMClient{sdk: &kvOnlyClient{kv: &recordingKVClient{err: errCoverage964e}}}
	got, token, err = failing.List(context.Background(), "ipam/pool", 50, "")
	if !errors.Is(err, errCoverage964e) || got != nil || token != "" {
		t.Fatalf("List() = (%v, %q, %v), want (nil, \"\", the KV error)", got, token, err)
	}
}

// Query has no SDK route: the IPAM backend answers index lookups from the
// explicit index keys it writes in Put, so Query returns an empty result.
func TestCoverage964e_SDKIPAMClientQuery(t *testing.T) {
	c := &sdkIPAMClient{sdk: &kvOnlyClient{kv: &recordingKVClient{err: errCoverage964e}}}
	got, err := c.Query(context.Background(), "ipam/lease", "mac", []byte("aa:bb"))
	if err != nil || got != nil {
		t.Fatalf("Query() = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestCoverage964e_SDNAccessors(t *testing.T) {
	app := &App{}
	if app.OVSClient() != nil {
		t.Fatal("OVSClient() is not nil before SDN init")
	}
	if app.IPAMAllocator() != nil {
		t.Fatal("IPAMAllocator() is not nil before SDN init")
	}
}

func TestCoverage964e_OVSRootRowRetryConfig(t *testing.T) {
	var retried []int
	cfg := ovsRootRowRetryConfig(func(attempt int, _ error, _ time.Duration) {
		retried = append(retried, attempt)
	})
	if cfg.MaxAttempts != ovsRootRowMaxAttempts {
		t.Fatalf("MaxAttempts = %d, want %d", cfg.MaxAttempts, ovsRootRowMaxAttempts)
	}
	backoff, ok := cfg.Backoff.(*quicbaassdk.ConstantBackoff)
	if !ok || backoff.Delay != ovsRootRowRetryInterval {
		t.Fatalf("Backoff = %#v, want a constant %v", cfg.Backoff, ovsRootRowRetryInterval)
	}
	if !cfg.RetryableFunc(errors.New("ovsdb: no Open_vSwitch row found")) {
		t.Fatal("the missing root row is not retried")
	}
	if cfg.RetryableFunc(errCoverage964e) {
		t.Fatal("an unrelated OVSDB error is retried")
	}
	cfg.OnRetry(2, errCoverage964e, time.Second)
	if len(retried) != 1 || retried[0] != 2 {
		t.Fatalf("OnRetry reached %v, want the caller's hook with attempt 2", retried)
	}
}

func TestCoverage964e_ResidentKeys(t *testing.T) {
	cfg := disklessTPMConfig()
	keys, err := residentKeys(&cfg)
	if err != nil {
		t.Fatalf("residentKeys() error = %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("residentKeys() returned %d keys, want 5", len(keys))
	}
	idevid := keys[4]
	if idevid.key != "idevid" || idevid.handle != testIDevIDHandle || idevid.restricted || !idevid.sign {
		t.Fatalf("idevid entry = %+v, want an unrestricted signing key", idevid)
	}
	iak := keys[3]
	if iak.key != "iak" || !iak.restricted || !iak.sign || iak.decrypt {
		t.Fatalf("iak entry = %+v, want a restricted signing key", iak)
	}

	unset := map[string]func(c *xkmssdk.TPMConfig){
		"ek":           func(c *xkmssdk.TPMConfig) { c.EK = nil },
		"ssrk":         func(c *xkmssdk.TPMConfig) { c.SSRK.Handle = 0 },
		"platform-srk": func(c *xkmssdk.TPMConfig) { c.PlatformSRK = nil },
		"iak":          func(c *xkmssdk.TPMConfig) { c.IAK.Handle = 0 },
		"idevid":       func(c *xkmssdk.TPMConfig) { c.IDevID = nil },
	}
	for key, mutate := range unset {
		t.Run(key, func(t *testing.T) {
			c := disklessTPMConfig()
			mutate(&c)
			_, err := residentKeys(&c)
			var want *ErrTPMHandleUnset
			if !errors.As(err, &want) || want.Key != key {
				t.Fatalf("residentKeys() error = %v, want ErrTPMHandleUnset{%s}", err, key)
			}
			if !strings.Contains(err.Error(), key+" persistent handle") {
				t.Fatalf("error %q does not name the %s handle", err, key)
			}
		})
	}
}

// typedErrorCase is one typed error, the text its message must carry and the
// cause errors.Is must reach through it (nil when it wraps nothing).
type typedErrorCase struct {
	err   error
	parts []string
	cause error
}

func TestCoverage964e_TypedErrors(t *testing.T) {
	cases := map[string]typedErrorCase{
		"ErrCANotConfigured": {
			err: ErrCANotConfigured{}, parts: []string{"no certificate authority"},
		},
		"ErrCAPINs": {
			err: ErrCAPINs{Cause: errCoverage964e}, parts: []string{"CA PINs"}, cause: errCoverage964e,
		},
		"CommandOutputError": {
			err:   &CommandOutputError{Msg: "ovs-vsctl", Err: errCoverage964e, Detail: " (stderr: denied)"},
			parts: []string{"ovs-vsctl: ", "(stderr: denied)"}, cause: errCoverage964e,
		},
		"ErrHeartbeatIntervalTooShort": {
			err:   ErrHeartbeatIntervalTooShort{Interval: time.Microsecond},
			parts: []string{"1µs", MinHeartbeatInterval.String()},
		},
		"ErrHeartbeatIdentityIncomplete": {
			err:   ErrHeartbeatIdentityIncomplete{CertFile: "/c.pem"},
			parts: []string{"cert-file and key-file must both be set"},
		},
		"ErrHeartbeatCABundleInvalid": {
			err: ErrHeartbeatCABundleInvalid{Path: "/ca.pem"}, parts: []string{"/ca.pem"},
		},
		"ErrPlatformAnchorNoIdentity": {
			err: ErrPlatformAnchorNoIdentity{}, parts: []string{"no TPM-backed IDevID"},
		},
		"ErrIDevIDPublicKeyMissing": {
			err: ErrIDevIDPublicKeyMissing{}, parts: []string{"no public key"},
		},
		"ErrBMCACMEIssuerUnavailable": {
			err: ErrBMCACMEIssuerUnavailable{DeviceID: "bmc-7"}, parts: []string{"bmc-7", "refusing to substitute"},
		},
		"ErrCertRenewalSweepIncomplete": {
			err:   ErrCertRenewalSweepIncomplete{Evaluated: 2, Total: 5, Cause: errCoverage964e},
			parts: []string{"evaluated 2 of 5"}, cause: errCoverage964e,
		},
		"ErrNTSProvision": {
			err: &ErrNTSProvision{Stage: "store key", Cause: errCoverage964e}, parts: []string{"nts-provision: store key"},
			cause: errCoverage964e,
		},
		"SOPINHandoffError": {
			err: &SOPINHandoffError{Stage: "read /run/x", Cause: errCoverage964e}, parts: []string{"sopin-handoff: read /run/x"},
			cause: errCoverage964e,
		},
		"ErrBootModelUnreadable": {
			err:   &ErrBootModelUnreadable{Path: "/proc/cmdline", Err: errCoverage964e},
			parts: []string{"cannot read /proc/cmdline"}, cause: errCoverage964e,
		},
		"ErrTPMHandleUnreadable": {
			err:   &ErrTPMHandleUnreadable{Handle: 0x81000001, Err: errCoverage964e},
			parts: []string{"0x81000001"}, cause: errCoverage964e,
		},
		"ErrDisklessBootUnconfigured": {
			err: ErrDisklessBootUnconfigured{Setting: "tpm.idevid.cn"}, parts: []string{"tpm.idevid.cn is not configured"},
		},
		"ErrDisklessBootMaterialInvalid": {
			err:   ErrDisklessBootMaterialInvalid{Reason: "key mismatch"},
			parts: []string{"refused: key mismatch"},
		},
		"SSRKProbeError": {
			err: &SSRKProbeError{Handle: 0x81000002, Cause: errCoverage964e}, parts: []string{"read the Shared SRK handle 0x81000002"},
			cause: errCoverage964e,
		},
		"SSRKCreateError": {
			err: &SSRKCreateError{Handle: 0x81000002, Cause: errCoverage964e}, parts: []string{"create the Shared SRK at 0x81000002"},
			cause: errCoverage964e,
		},
		"ErrSecureBootProvisionNoCause": {
			err: &ErrSecureBootProvision{Role: "db", Stage: "self-sign"}, parts: []string{"secureboot-provision: db: self-sign"},
		},
		"ErrSecureBootSecretsUnavailable": {
			err: &ErrSecureBootSecretsUnavailable{}, parts: []string{"SecretsService not available"},
		},
		"ErrSecureBootExistenceCheck": {
			err: &ErrSecureBootExistenceCheck{Path: "kms://sb/pk", Cause: errCoverage964e}, parts: []string{"kms://sb/pk", "refusing to overwrite"},
			cause: errCoverage964e,
		},
		"ErrCertInstallerMissing": {
			err: ErrCertInstallerMissing{Webservice: "admin"}, parts: []string{"webservice admin has no certificate installer"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, part := range tc.parts {
				if !strings.Contains(msg, part) {
					t.Fatalf("Error() = %q, want it to contain %q", msg, part)
				}
			}
			if tc.cause != nil {
				if !errors.Is(tc.err, tc.cause) || !strings.Contains(msg, tc.cause.Error()) {
					t.Fatalf("%q does not wrap and name its cause", msg)
				}
			} else if errors.Is(tc.err, errCoverage964e) {
				t.Fatalf("%q wraps a cause it was not given", msg)
			}
		})
	}
}

// The value-type sentinels match their own type through errors.Is and
// nothing else.
func TestCoverage964e_ValueErrorIs(t *testing.T) {
	if !errors.Is(&WrappedError{Msg: "anchor", Err: ErrPlatformAnchorNoIdentity{}}, ErrPlatformAnchorNoIdentity{}) {
		t.Fatal("a wrapped ErrPlatformAnchorNoIdentity is not matched")
	}
	if (ErrPlatformAnchorNoIdentity{}).Is(ErrIDevIDPublicKeyMissing{}) {
		t.Fatal("ErrPlatformAnchorNoIdentity matches another type")
	}
	if !errors.Is(&WrappedError{Msg: "signer", Err: ErrIDevIDPublicKeyMissing{}}, ErrIDevIDPublicKeyMissing{}) {
		t.Fatal("a wrapped ErrIDevIDPublicKeyMissing is not matched")
	}
	if (ErrIDevIDPublicKeyMissing{}).Is(errCoverage964e) {
		t.Fatal("ErrIDevIDPublicKeyMissing matches another error")
	}
}

func TestCoverage964e_ShredAndUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.key")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := shredAndUnlink(path, len("secret")); err != nil {
		t.Fatalf("shredAndUnlink() error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the shredded file is still present: %v", err)
	}
	// A missing file is already gone: nothing to shred.
	if err := shredAndUnlink(path, 6); err != nil {
		t.Fatalf("shredAndUnlink() on a missing file error = %v, want nil", err)
	}
	// A directory cannot be opened for writing.
	if err := shredAndUnlink(t.TempDir(), 6); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shredAndUnlink() on a directory error = %v, want an open failure", err)
	}
}

func TestCoverage964e_ShredSOPINHandoff(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	path := filepath.Join(t.TempDir(), "so-pin")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.shredSOPINHandoff(path, 4); err != nil {
		t.Fatalf("shredSOPINHandoff() error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the staged SO PIN is still present: %v", err)
	}

	dir := t.TempDir()
	err := app.shredSOPINHandoff(dir, 4)
	var handoff *SOPINHandoffError
	if !errors.As(err, &handoff) || handoff.Stage != "shred "+dir {
		t.Fatalf("shredSOPINHandoff() on a directory error = %v, want SOPINHandoffError at the shred stage", err)
	}
}

func TestCoverage964e_StoreFactoryAdapters(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	memory := NewCAStoreFactory(app, t.TempDir(), object.NewMemoryClient(), nil, nil)
	unbacked := NewCAStoreFactory(app, t.TempDir(), nil, nil, nil)

	t.Run("cert store", func(t *testing.T) {
		cs, err := certStoreFactoryAdapter(memory)("root-ca")
		if err != nil || cs == nil {
			t.Fatalf("certStoreFactoryAdapter() = (%v, %v), want a cert store", cs, err)
		}
		if _, err := certStoreFactoryAdapter(unbacked)("root-ca"); err == nil || !strings.Contains(err.Error(), "root-ca") {
			t.Fatalf("certStoreFactoryAdapter() without storage error = %v, want one naming the CA", err)
		}
	})
	t.Run("object store", func(t *testing.T) {
		store, err := objectStoreFactoryAdapter(memory)("root-ca")
		if err != nil || store == nil {
			t.Fatalf("objectStoreFactoryAdapter() = (%v, %v), want an object store", store, err)
		}
	})
	t.Run("key store without quicbaas", func(t *testing.T) {
		ks, err := keyStoreFactoryAdapter(memory)("root-ca")
		var msg *MessageError
		if !errors.As(err, &msg) || ks != nil || !strings.Contains(msg.Msg, "QuicBaaS service not initialized") {
			t.Fatalf("keyStoreFactoryAdapter() = (%v, %v), want the QuicBaaS-not-initialized error", ks, err)
		}
	})
}
