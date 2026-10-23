package disklessroot

import (
	"errors"
	"strings"
	"testing"
)

func testParams(t *testing.T) BootParams {
	t.Helper()
	params, err := NewBootParams(testManifest(), "http://boot.example.com/data/sets/aarch64-rpi")
	if err != nil {
		t.Fatalf("NewBootParams: %v", err)
	}
	return params
}

func TestNewBootParamsLocatesTheArtifactsBesideTheSet(t *testing.T) {
	params := testParams(t)
	want := BootParams{
		RootFSURL:  "http://boot.example.com/data/sets/aarch64-rpi/" + RootFSFile,
		VerityURL:  "http://boot.example.com/data/sets/aarch64-rpi/" + VerityFile,
		RootHash:   testRootHash,
		Salt:       testSalt,
		RootFSSize: 64 * BlockSize,
		VeritySize: 2 * BlockSize,
	}
	if params != want {
		t.Fatalf("NewBootParams = %+v, want %+v", params, want)
	}
	trailing, err := NewBootParams(testManifest(), "http://boot.example.com/data/sets/aarch64-rpi/")
	if err != nil || trailing != want {
		t.Fatalf("NewBootParams with a trailing slash = %+v, %v", trailing, err)
	}
}

func TestNewBootParamsErrors(t *testing.T) {
	var fieldErr *FieldError
	if _, err := NewBootParams(testManifest(), "ftp://boot.example.com/set"); !errors.As(err, &fieldErr) {
		t.Fatalf("NewBootParams with an ftp base = %v, want a FieldError", err)
	}
	bad := testManifest()
	bad.RootHash = "nope"
	if _, err := NewBootParams(bad, "http://boot.example.com/set"); !errors.As(err, &fieldErr) {
		t.Fatalf("NewBootParams with an invalid manifest = %v, want a FieldError", err)
	}
}

func TestBootParamsArgsRoundTrip(t *testing.T) {
	params := testParams(t)
	args := params.Args()
	if args[0] != ParamBootModel+"="+BootModel {
		t.Fatalf("Args()[0] = %q, want the boot model first", args[0])
	}
	got, ok, err := ParamsFromCmdline("console=ttyS0 " + strings.Join(args, " ") + " quiet")
	if err != nil || !ok {
		t.Fatalf("ParamsFromCmdline(Args()) = %v, %v", ok, err)
	}
	if got != params {
		t.Fatalf("round trip = %+v, want %+v", got, params)
	}
	if got.DataBlocks() != 64 {
		t.Fatalf("DataBlocks() = %d, want 64", got.DataBlocks())
	}
}

func TestParamsFromCmdlineWithoutTheBootModelIsNotDiskless(t *testing.T) {
	params := testParams(t)
	// Stray root parameters on a disk node's command line do not make it
	// diskless: only the boot model selects the path.
	stray := strings.Join(params.Args()[1:], " ")
	got, ok, err := ParamsFromCmdline("root=/dev/mapper/root " + stray)
	if err != nil || ok || got != (BootParams{}) {
		t.Fatalf("ParamsFromCmdline without the boot model = %+v, %v, %v", got, ok, err)
	}
}

func TestParamsFromCmdlineErrors(t *testing.T) {
	params := testParams(t)
	valid := params.Args()
	cases := map[string]struct {
		cmdline string
		field   string
	}{
		"duplicate root hash": {
			cmdline: strings.Join(valid, " ") + " " + ParamRootHash + "=" + strings.Repeat("a", 64),
			field:   ParamRootHash,
		},
		"duplicate boot model": {
			cmdline: strings.Join(valid, " ") + " " + ParamBootModel + "=" + BootModel,
			field:   ParamBootModel,
		},
		"unknown boot model": {
			cmdline: ParamBootModel + "=nfs",
			field:   ParamBootModel,
		},
		"missing root hash": {
			cmdline: strings.Join(without(valid, ParamRootHash), " "),
			field:   ParamRootHash,
		},
		"missing rootfs url": {
			cmdline: strings.Join(without(valid, ParamRootFSURL), " "),
			field:   ParamRootFSURL,
		},
		"bad scheme": {
			cmdline: strings.Join(replace(valid, ParamVerityURL, "file:///etc/passwd"), " "),
			field:   ParamVerityURL,
		},
		"no host": {
			cmdline: strings.Join(replace(valid, ParamRootFSURL, "http:///rootfs"), " "),
			field:   ParamRootFSURL,
		},
		"bad salt": {
			cmdline: strings.Join(replace(valid, ParamVeritySalt, "xyz"), " "),
			field:   ParamVeritySalt,
		},
		"size not a number": {
			cmdline: strings.Join(replace(valid, ParamRootFSSize, "lots"), " "),
			field:   ParamRootFSSize,
		},
		"unaligned rootfs size": {
			cmdline: strings.Join(replace(valid, ParamRootFSSize, "4097"), " "),
			field:   ParamRootFSSize,
		},
		"zero verity size": {
			cmdline: strings.Join(replace(valid, ParamVeritySize, "0"), " "),
			field:   ParamVeritySize,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var fieldErr *FieldError
			_, _, err := ParamsFromCmdline(tc.cmdline)
			if !errors.As(err, &fieldErr) || fieldErr.Field != tc.field {
				t.Fatalf("ParamsFromCmdline = %v, want a %s FieldError", err, tc.field)
			}
		})
	}
}

func TestBootModelFromCmdline(t *testing.T) {
	for cmdline, want := range map[string]string{
		"":                     "",
		"root=/dev/sda2 quiet": "",
		"ip=dhcp " + ParamBootModel + "=" + BootModel: BootModel,
	} {
		got, err := BootModelFromCmdline(cmdline)
		if err != nil || got != want {
			t.Fatalf("BootModelFromCmdline(%q) = %q, %v, want %q", cmdline, got, err, want)
		}
	}
	var fieldErr *FieldError
	if _, err := BootModelFromCmdline(ParamBootModel + "=diskless " + ParamBootModel + "=diskless"); !errors.As(err, &fieldErr) {
		t.Fatalf("BootModelFromCmdline with a duplicate = %v, want a FieldError", err)
	}
	if _, err := BootModelFromCmdline(ParamBootModel + "=iscsi"); !errors.As(err, &fieldErr) {
		t.Fatalf("BootModelFromCmdline with an unknown model = %v, want a FieldError", err)
	}
}

func without(args []string, key string) []string {
	var out []string
	for _, arg := range args {
		if !strings.HasPrefix(arg, key+"=") {
			out = append(out, arg)
		}
	}
	return out
}

func replace(args []string, key, value string) []string {
	out := without(args, key)
	return append(out, key+"="+value)
}
