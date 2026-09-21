package diskimage

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// Defaults for `diskimage test boot`.
const (
	defaultTestImage    = "bin/trusted-platform-qemu-virt.img"
	defaultTestFirmware = pkgdiskimage.DefaultUBootBuilderDir + "/output/" + string(uboot.BoardQEMUArm64) + "/u-boot.bin"
	defaultTestTimeout  = 45 * time.Minute
)

// testFlags are the flags of `diskimage test boot`.
type testFlags struct {
	image         string
	inPlace       bool
	firmware      string
	workDir       string
	memory        int
	cpus          int
	serialLog     string
	consoleSocket string
	expect        string
	timeout       time.Duration
	forwards      []string
	debug         bool
}

func newTestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Boot a factory image under emulation",
		Long: `Boot a factory image in QEMU with a software TPM.

The qemu-virt image is the emulated stand-in for the Raspberry Pi: the
same Alpine aarch64 install, EFI partition, U-Boot boot flow and first
boot, on the QEMU virt machine with U-Boot supplied as -bios and a swtpm
behind tpm-tis-device. Booting it proves the chain the SD card relies on
(U-Boot → Secure Boot → UKI → platform-initrd → firstboot → platformd)
without the hardware.`,
	}
	cmd.AddCommand(newTestBootCommand(getFlags))
	return cmd
}

func newTestBootCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &testFlags{}
	cmd := &cobra.Command{
		Use:   "boot",
		Short: "Boot an image (interactive console, or wait for a serial milestone)",
		Long: `Boot a factory image on the QEMU virt machine.

Without --serial-log the guest console is on this terminal (Ctrl-A X
quits QEMU). With --serial-log the transcript goes to that file, and with
--expect the command returns as soon as the text appears in it, which is
how the integration suite and a CI job wait for first boot to finish.
The image is copied into the work directory before boot unless
--in-place is given; the TPM state under <work-dir>/tpm is kept between
boots so a second boot can unseal what the first sealed.

Examples:
  # interactive first boot of the QEMU stand-in
  platformctl diskimage test boot

  # unattended: return once platformd is up, keep the transcript
  platformctl diskimage test boot --serial-log work/diskimage-test/boot1.log \
    --expect "platformd ready" --forward 18443:8443

  # second boot of the same disk and TPM state
  platformctl diskimage test boot --image work/diskimage-test/disk.img --in-place \
    --serial-log work/diskimage-test/boot2.log --expect "Successfully unlocked"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestBoot(getFlags(), flags)
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.image, "image", defaultTestImage, "Factory image to boot")
	f.BoolVar(&flags.inPlace, "in-place", false, "Boot the image itself instead of a copy under --work-dir")
	f.StringVar(&flags.firmware, "uboot", defaultTestFirmware, "qemu_arm64 U-Boot binary passed as -bios")
	f.StringVar(&flags.workDir, "work-dir", pkgdiskimage.DefaultBootWorkDir, "TPM state, sockets and the working copy of the image")
	f.IntVar(&flags.memory, "memory", pkgdiskimage.DefaultBootMemory, "Guest RAM in MB")
	f.IntVar(&flags.cpus, "cpus", 0, "Guest CPUs (default: up to 4)")
	f.StringVar(&flags.serialLog, "serial-log", "", "Write the serial transcript to this file instead of the terminal")
	f.StringVar(&flags.consoleSocket, "console-socket", "", "Also expose the console on this unix socket")
	f.StringVar(&flags.expect, "expect", "", "Return once this text appears in --serial-log")
	f.DurationVar(&flags.timeout, "timeout", defaultTestTimeout, "Give up waiting for --expect after this long (TCG emulation is slow)")
	f.StringArrayVar(&flags.forwards, "forward", nil, "User-mode port forward host:guest[/udp], repeatable")
	f.BoolVar(&flags.debug, "debug", false, "Debug output from QEMU and swtpm")
	return cmd
}

// runTestBoot is the command body: it turns the flags into BootOptions
// and hands them to the package.
func runTestBoot(commonFlags *cli.CommonFlags, flags *testFlags) error {
	forwards, err := parsePortForwards(flags.forwards)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if flags.expect != "" {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, flags.timeout)
		defer cancelTimeout()
	}

	logger := logging.DefaultLogger()
	result, err := pkgdiskimage.Boot(ctx, pkgdiskimage.BootOptions{
		Image:         flags.image,
		InPlace:       flags.inPlace,
		Firmware:      flags.firmware,
		WorkDir:       flags.workDir,
		Memory:        flags.memory,
		CPUs:          flags.cpus,
		SerialLog:     flags.serialLog,
		ConsoleSocket: flags.consoleSocket,
		Expect:        flags.expect,
		PortForwards:  forwards,
		Debug:         flags.debug,
		Logger:        logger,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Booted %s (TPM state %s)\n", result.Disk, result.TPMState)
	if result.Expected {
		fmt.Printf("  milestone reached: %q\n", flags.expect)
	}
	if result.SerialLog != "" {
		fmt.Printf("  serial transcript: %s\n", result.SerialLog)
	}
	return nil
}

// parsePortForwards parses host:guest[/proto] forwards.
func parsePortForwards(specs []string) ([]qemu.PortForward, error) {
	forwards := make([]qemu.PortForward, 0, len(specs))
	for _, spec := range specs {
		proto := "tcp"
		ports := spec
		if i := strings.LastIndex(spec, "/"); i >= 0 {
			proto = spec[i+1:]
			ports = spec[:i]
		}
		hostStr, guestStr, ok := strings.Cut(ports, ":")
		if !ok {
			return nil, ErrInvalidPortForward{Spec: spec}
		}
		host, err := strconv.Atoi(hostStr)
		if err != nil {
			return nil, ErrInvalidPortForward{Spec: spec}
		}
		guest, err := strconv.Atoi(guestStr)
		if err != nil {
			return nil, ErrInvalidPortForward{Spec: spec}
		}
		if proto != "tcp" && proto != "udp" {
			return nil, ErrInvalidPortForward{Spec: spec}
		}
		forwards = append(forwards, qemu.PortForward{HostPort: host, GuestPort: guest, Protocol: proto})
	}
	return forwards, nil
}
