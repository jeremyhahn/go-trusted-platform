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

package rpinetboot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/fatimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
)

// The files the bootloader fetches from HTTP_HOST/HTTP_PATH.
const (
	HTTPBootImage     = "boot.img"
	HTTPBootSignature = "boot.sig"
)

// Defaults for HTTPBootOptions.
const (
	// HTTPTimeout bounds one request; boot.img is tens of megabytes.
	HTTPTimeout = 2 * time.Minute
	// MaxImageBytes bounds boot.img: the ramdisk is held in memory.
	MaxImageBytes = 256 << 20
	// maxSignatureBytes bounds boot.sig, which is under a kilobyte.
	maxSignatureBytes = 4 << 10
)

// HTTPBootOptions configures HTTPBoot: which server to fetch from and the
// keys the bootloader holds.
type HTTPBootOptions struct {
	// Host is the EEPROM's HTTP_HOST (an address, with a port if not 80) and
	// Path its HTTP_PATH.
	Host string
	Path string
	// PublicKey is the fleet key as the EEPROM carries it (pubkey.bin). The
	// bootloader verifies boot.sig with it.
	PublicKey []byte
	// OTPKeyHash is the customer key hash in OTP: the SHA-256 of PublicKey the
	// bootloader requires before it trusts the key.
	OTPKeyHash [rpibootsig.KeyHashSize]byte

	// Client makes the requests; a client with HTTPTimeout when nil.
	Client *http.Client
	// MaxImageBytes bounds boot.img (MaxImageBytes when zero).
	MaxImageBytes int64
	// Logger receives the exchange as it happens; nil means the default.
	Logger *logging.Logger
}

// HTTPBootReport is what a signed HTTP boot saw.
type HTTPBootReport struct {
	// URL is the directory boot.img and boot.sig were fetched from.
	URL string
	// Image describes boot.img as received.
	Image FileReport
	// Signature is the verified boot.sig.
	Signature *rpibootsig.Signature
	// Ramdisk lists the files of the FAT ramdisk boot.img holds.
	Ramdisk []string
}

// HTTPBoot boots from the network the way a Raspberry Pi 4 or 5 with
// BOOT_ORDER's HTTP nibble and SIGNED_BOOT=1 does: it fetches boot.img and
// boot.sig from http://HTTP_HOST/HTTP_PATH/, requires the EEPROM's public key
// to hash to the key hash in OTP, verifies boot.sig over boot.img with it, and
// mounts the image as the FAT ramdisk the bootloader boots from. Anything the
// bootloader would refuse is an error: it never reports an image it would not
// run.
func HTTPBoot(ctx context.Context, opts HTTPBootOptions) (*HTTPBootReport, error) {
	if opts.Host == "" {
		return nil, &HTTPBootConfigError{Field: "Host"}
	}
	pub, err := rpibootsig.ParseKeyBlob(opts.PublicKey)
	if err != nil {
		return nil, &HTTPBootConfigError{Field: "PublicKey", Err: err}
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: HTTPTimeout}
	}
	if opts.MaxImageBytes == 0 {
		opts.MaxImageBytes = MaxImageBytes
	}
	if opts.Logger == nil {
		opts.Logger = logging.DefaultLogger()
	}
	base := "http://" + opts.Host
	if path := strings.Trim(opts.Path, "/"); path != "" {
		base += "/" + path
	}

	image, err := opts.fetch(ctx, base, HTTPBootImage, opts.MaxImageBytes)
	if err != nil {
		return nil, err
	}
	sigFile, err := opts.fetch(ctx, base, HTTPBootSignature, maxSignatureBytes)
	if err != nil {
		return nil, err
	}
	sig, err := rpibootsig.Verify(sigFile, image, pub, opts.OTPKeyHash)
	if err != nil {
		return nil, &HTTPBootRefusedError{URL: base, Err: err}
	}
	opts.Logger.Info("boot.sig verified", "url", base, "ts", sig.Timestamp.Unix(), "target-soc", sig.TargetSoC)

	ramdisk, err := fatimage.Open(image)
	if err != nil {
		return nil, &RamdiskError{Err: err}
	}
	files, err := ramdisk.Files()
	if err != nil {
		return nil, &RamdiskError{Err: err}
	}
	digest := sha256.Sum256(image)
	return &HTTPBootReport{
		URL:       base,
		Image:     FileReport{Name: HTTPBootImage, Path: base + "/" + HTTPBootImage, Bytes: int64(len(image)), SHA256: hex.EncodeToString(digest[:])},
		Signature: sig,
		Ramdisk:   files,
	}, nil
}

// fetch GETs base/name, refusing a body over limit.
func (o *HTTPBootOptions) fetch(ctx context.Context, base, name string, limit int64) ([]byte, error) {
	url := base + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &HTTPFetchError{URL: url, Err: err}
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, &HTTPFetchError{URL: url, Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		if err := resp.Body.Close(); err != nil {
			return nil, &HTTPFetchError{URL: url, Err: err}
		}
		return nil, &HTTPFetchError{URL: url, Err: &HTTPStatusError{Status: resp.StatusCode}}
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, &HTTPFetchError{URL: url, Err: readErr}
	}
	if closeErr != nil {
		return nil, &HTTPFetchError{URL: url, Err: closeErr}
	}
	if int64(len(data)) > limit {
		return nil, &HTTPFetchError{URL: url, Err: &HTTPSizeError{Limit: limit}}
	}
	o.Logger.Info("Fetched", "url", url, "bytes", len(data))
	return data, nil
}
