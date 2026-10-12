package disklessroot

import (
	"net/url"
	"strconv"
	"strings"
)

// Kernel command line parameters. ParamBootModel alone selects the diskless
// path; the rest describe the root and are only read when it does. The root
// hash is platform_roothash, not roothash: systemd-veritysetup-generator owns
// roothash= and would try to open a verity device of its own.
const (
	ParamBootModel  = "platform_boot_model"
	ParamRootFSURL  = "platform_rootfs_url"
	ParamVerityURL  = "platform_verity_url"
	ParamRootHash   = "platform_roothash"
	ParamVeritySalt = "platform_verity_salt"
	ParamRootFSSize = "platform_rootfs_size"
	ParamVeritySize = "platform_verity_size"
)

// ownedParams are the parameters this package reads. Each may appear at most
// once: with two values, which one the kernel, the dracut hook and Go each
// pick would be three separate decisions.
var ownedParams = map[string]bool{
	ParamBootModel:  true,
	ParamRootFSURL:  true,
	ParamVerityURL:  true,
	ParamRootHash:   true,
	ParamVeritySalt: true,
	ParamRootFSSize: true,
	ParamVeritySize: true,
}

// BootParams are the diskless root parameters the installer writes into the
// signed UKI command line and platform-initrd reads back.
type BootParams struct {
	RootFSURL  string
	VerityURL  string
	RootHash   string
	Salt       string
	RootFSSize int64
	VeritySize int64
}

// NewBootParams turns a verified manifest into boot parameters. baseURL is the
// media set's directory on the boot server; the artifacts sit in it under
// their fixed names. The URLs only locate the bytes: dm-verity under the
// signed root hash decides whether they are the right ones.
func NewBootParams(m Manifest, baseURL string) (BootParams, error) {
	if err := m.Validate(); err != nil {
		return BootParams{}, err
	}
	base := strings.TrimRight(baseURL, "/")
	params := BootParams{
		RootFSURL:  base + "/" + RootFSFile,
		VerityURL:  base + "/" + VerityFile,
		RootHash:   m.RootHash,
		Salt:       m.Salt,
		RootFSSize: m.RootFSSize,
		VeritySize: m.VeritySize,
	}
	if err := params.Validate(); err != nil {
		return BootParams{}, err
	}
	return params, nil
}

// Validate checks every parameter.
func (p BootParams) Validate() error {
	if err := validateURL(ParamRootFSURL, p.RootFSURL); err != nil {
		return err
	}
	if err := validateURL(ParamVerityURL, p.VerityURL); err != nil {
		return err
	}
	if err := ValidateRootHash(p.RootHash); err != nil {
		return err
	}
	if err := validateHex(ParamVeritySalt, p.Salt); err != nil {
		return err
	}
	return validateSizes(p.RootFSSize, p.VeritySize)
}

// DataBlocks is the number of dm-verity data blocks the root image covers.
func (p BootParams) DataBlocks() int64 {
	return p.RootFSSize / BlockSize
}

// Args renders the parameters, boot model first, for a kernel command line.
func (p BootParams) Args() []string {
	return []string{
		ParamBootModel + "=" + BootModel,
		ParamRootFSURL + "=" + p.RootFSURL,
		ParamVerityURL + "=" + p.VerityURL,
		ParamRootHash + "=" + p.RootHash,
		ParamVeritySalt + "=" + p.Salt,
		ParamRootFSSize + "=" + strconv.FormatInt(p.RootFSSize, 10),
		ParamVeritySize + "=" + strconv.FormatInt(p.VeritySize, 10),
	}
}

// BootModelFromCmdline returns the boot model a kernel command line names:
// BootModel, or "" for a node that boots from its own disk.
func BootModelFromCmdline(cmdline string) (string, error) {
	values, err := scanCmdline(cmdline)
	if err != nil {
		return "", err
	}
	return values[ParamBootModel], nil
}

// ParamsFromCmdline reads the diskless root parameters from a kernel command
// line. ok is false, and the parameters zero, unless the command line names
// the diskless boot model: stray root parameters on a disk node's command line
// select nothing. A diskless command line must carry every parameter, valid.
func ParamsFromCmdline(cmdline string) (BootParams, bool, error) {
	values, err := scanCmdline(cmdline)
	if err != nil {
		return BootParams{}, false, err
	}
	if values[ParamBootModel] != BootModel {
		return BootParams{}, false, nil
	}
	rootfsSize, err := parseSize(ParamRootFSSize, values[ParamRootFSSize])
	if err != nil {
		return BootParams{}, true, err
	}
	veritySize, err := parseSize(ParamVeritySize, values[ParamVeritySize])
	if err != nil {
		return BootParams{}, true, err
	}
	params := BootParams{
		RootFSURL:  values[ParamRootFSURL],
		VerityURL:  values[ParamVerityURL],
		RootHash:   values[ParamRootHash],
		Salt:       values[ParamVeritySalt],
		RootFSSize: rootfsSize,
		VeritySize: veritySize,
	}
	if err := params.Validate(); err != nil {
		return BootParams{}, true, err
	}
	return params, true, nil
}

// scanCmdline collects the owned parameters, refusing a repeated one and a
// boot model this package does not know.
func scanCmdline(cmdline string) (map[string]string, error) {
	values := map[string]string{}
	for _, field := range strings.Fields(cmdline) {
		key, value, _ := strings.Cut(field, "=")
		if !ownedParams[key] {
			continue
		}
		if _, seen := values[key]; seen {
			return nil, &FieldError{Field: key, Reason: "appears more than once on the kernel command line"}
		}
		values[key] = value
	}
	if model, ok := values[ParamBootModel]; ok && model != BootModel {
		return nil, &FieldError{Field: ParamBootModel, Reason: "must be " + BootModel + ", got " + strconv.Quote(model)}
	}
	return values, nil
}

func parseSize(field, value string) (int64, error) {
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, &FieldError{Field: field, Reason: "must be a size in bytes, got " + strconv.Quote(value)}
	}
	return size, nil
}

// validateURL accepts an absolute http or https URL with a host.
func validateURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return &FieldError{Field: field, Reason: "must be an absolute http or https URL"}
	}
	return nil
}
