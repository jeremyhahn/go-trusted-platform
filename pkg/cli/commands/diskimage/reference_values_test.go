package diskimage

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

type recordingRegistrar struct{ sums []string }

func (r *recordingRegistrar) RegisterManifest(_ context.Context, sum string, _ []byte) error {
	r.sums = append(r.sums, sum)
	return nil
}

// A measured CLI build hands Create the registrar the command resolves from
// its platform client, so Create registers the signed manifest through it.
func TestImageBuildSetsReferenceValues(t *testing.T) {
	reg := &recordingRegistrar{}
	lazy := cli.NewLazyClient(&cli.CommonFlags{})
	var got *cli.LazyClient
	restore := referenceValues
	referenceValues = func(c *cli.LazyClient) pkgdiskimage.ReferenceValueRegistrar {
		got = c
		return reg
	}
	t.Cleanup(func() { referenceValues = restore })

	iso := &pkgiso.ISOBuildConfig{SecureBoot: true}
	build := (&mediaFlags{}).imageBuild(iso, lazy, nil)
	if got != lazy {
		t.Fatalf("referenceValues called with %p, want the command's platform client %p", got, lazy)
	}
	if build.ReferenceValues != pkgdiskimage.ReferenceValueRegistrar(reg) {
		t.Fatalf("BuildConfig.ReferenceValues = %v, want the command's registrar", build.ReferenceValues)
	}
	if err := build.ReferenceValues.RegisterManifest(context.Background(), "ab", nil); err != nil || len(reg.sums) != 1 {
		t.Fatalf("registrar not reached: %v %v", err, reg.sums)
	}
}

// The pinned go-quicbaas SDK has no reference-values verb, so the production
// resolver yields no registrar: a measured build signs and writes its
// manifest beside the image, warns, and leaves it unregistered
// (Result.Registered false) until the SDK bump (#1348).
func TestProductionReferenceValuesUnavailable(t *testing.T) {
	if reg := referenceValues(cli.NewLazyClient(&cli.CommonFlags{})); reg != nil {
		t.Fatalf("referenceValues() = %v, want nil until the SDK carries PutReferenceValues", reg)
	}
}
