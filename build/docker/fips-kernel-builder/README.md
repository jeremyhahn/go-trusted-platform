# FIPS Kernel Builder

This Docker container builds a FIPS-capable Linux kernel with CONFIG_CRYPTO_FIPS enabled.

## Why Pre-Build?

Alpine Linux kernels do NOT have built-in FIPS support by default. To enable FIPS mode, we need a custom kernel with CONFIG_CRYPTO_FIPS enabled.

Instead of compiling the kernel during installation (which takes 15-30 minutes and requires significant resources), we pre-build the kernel in this Docker container and include it in the ISO.

## Kernel Version

We use Linux 6.12.8 to match Alpine 3.22 LTS (NOT 6.13 which is bleeding edge).

## FIPS Configuration

The kernel is built with:

- `CONFIG_CRYPTO_FIPS=y` - Enable FIPS mode
- `CONFIG_CRYPTO_FIPS_NAME="Trusted Platform FIPS 140-3"`
- All required crypto algorithms (SHA256, SHA512, AES, etc.)
- `CONFIG_MODULE_SIG=y` - Module signing (required for FIPS)
- `CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=n` - Enable crypto self-tests (required for FIPS)
- TPM support (built-in for early boot)
- LUKS/dm-crypt support
- The platform-required options shared with the virt kernel builder,
  `build/docker/kernel-config/platform-required.config`: the overlay datapath
  (OVS, VXLAN), IPsec (ESP, XFRM_USER, GCM), conntrack/NAT, VRF, vsock,
  `MODULE_SIG_FORCE`, the lockdown LSM, IMA appraisal, core scheduling,
  `CRYPTO_FIPS` and the DRBG. The fragment is baked into the image through the
  `kernelconfig` named build context (`docker build --build-context
  kernelconfig=../kernel-config`), merged after the settings in
  `build-fips-kernel.sh`, and `require-config.sh` fails the build if
  `olddefconfig` dropped or changed any of its lines.

## Module-Signing Key (Production)

Production kernels embed the STABLE platform module-signing key
(`CONFIG_MODULE_SIG_KEY`) so out-of-tree modules signed with `pkg/modulesign`
load under `CONFIG_MODULE_SIG_FORCE`. Generate it once per platform, outside
the repository, and back it up:

```bash
# one-time (default output: ~/.trusted-platform/secure-boot/module-signing-key.pem)
make module-key            # wraps: platformctl iso module-signing-key

# every production build
make build MODULE_SIGNING_KEY=$HOME/.trusted-platform/secure-boot/module-signing-key.pem
```

The key is mounted read-only into the build container; it never enters the
build context or an image layer. Without `MODULE_SIGNING_KEY` the kernel
auto-generates a per-build ephemeral key (dev builds only — out-of-tree
signing is then impossible). See `docs/firmware/secure-boot.md`.

## Usage

Build the FIPS kernel:

```bash
make build
```

This will:
1. Build the Docker image (with the `kernelconfig` build context)
2. Download and cryptographically verify the kernel source from kernel.org
3. Configure the kernel with FIPS enabled and the platform-required options, and fail if any was dropped
4. Compile the kernel and modules
5. Extract artifacts to `output/`

Check the configuration only (defconfig, the settings, the required fragment,
`olddefconfig`, `require-config.sh`; nothing is compiled):

```bash
make config-check
```

Clean build artifacts:

```bash
make clean
```

Test the built kernel:

```bash
make test
```

## Output

After building, you'll find in `output/`:

- `vmlinuz-fips` - The FIPS-capable kernel image
- `modules-fips-${KVER}.tar.gz` - Kernel modules
- `System.map-fips` - System map for debugging
- `config-fips` - Kernel configuration
- `kernel-version.txt` - Kernel version string
- `*.sha256` - SHA256 checksums

## Integration

The FIPS kernel is automatically included in the ISO during the build process and installed during the Alpine installation. See `pkg/installer/alpine/fips.go` for integration details.

## Reference

This follows the architecture from the reference Alpine project:
- Uses kernel 6.12.8 (Alpine 3.22 LTS version)
- Same FIPS configuration approach
- Cryptographic verification using official kernel.org script
