// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/spf13/cobra"
)

const (
	cliTestDICEDeviceID = "a1b2c3d4e5f60718"
	cliTestGoldenFWHash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

// TestProfileDICEFlags_RoundTrip pins #1699 on the CLI: --dice-device-id and
// --golden-fw-hash parse into the create message, an update applies them,
// an update without them keeps the fetched values, and the output map
// reports them.
func TestProfileDICEFlags_RoundTrip(t *testing.T) {
	var pf profileFlags
	cmd := &cobra.Command{Use: "create"}
	registerProfileFlags(cmd, &pf)
	if err := cmd.ParseFlags([]string{"--name", "node-dice", "--dice-device-id", cliTestDICEDeviceID, "--golden-fw-hash", cliTestGoldenFWHash}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	created := newProfileCreateMessage(&pf, platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, "", nil)
	if created.GetDiceDeviceId() != cliTestDICEDeviceID || created.GetGoldenFwHash() != cliTestGoldenFWHash {
		t.Fatalf("create message = %q / %q", created.GetDiceDeviceId(), created.GetGoldenFwHash())
	}

	output := buildProfileOutput(created)
	if output["dice_device_id"] != cliTestDICEDeviceID || output["golden_fw_hash"] != cliTestGoldenFWHash {
		t.Fatalf("output = %v", output)
	}
	bare := buildProfileOutput(&platformv1.DeviceProfile{Id: 1, Name: "bare"})
	if _, present := bare["dice_device_id"]; present {
		t.Fatal("an absent dice_device_id must be omitted")
	}
	if _, present := bare["golden_fw_hash"]; present {
		t.Fatal("an absent golden_fw_hash must be omitted")
	}

	fetched := &platformv1.DeviceProfile{Id: 7, Name: "node-dice", DiceDeviceId: cliTestDICEDeviceID, GoldenFwHash: cliTestGoldenFWHash}
	if err := applyProfileUpdateFlags(fetched, &profileFlags{model: "m"}, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetched.GetDiceDeviceId() != cliTestDICEDeviceID || fetched.GetGoldenFwHash() != cliTestGoldenFWHash {
		t.Fatal("an update without the DICE flags must keep the fetched values")
	}

	newHash := "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := applyProfileUpdateFlags(fetched, &profileFlags{diceDeviceID: "beef", goldenFWHash: newHash}, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetched.GetDiceDeviceId() != "beef" || fetched.GetGoldenFwHash() != newHash {
		t.Fatalf("update flags not applied: %q / %q", fetched.GetDiceDeviceId(), fetched.GetGoldenFwHash())
	}

	for _, sub := range newProfileCommand(nil).Commands() {
		if sub.Name() != "create" && sub.Name() != "update" {
			continue
		}
		for _, flag := range []string{"dice-device-id", "golden-fw-hash"} {
			if sub.Flags().Lookup(flag) == nil {
				t.Errorf("%s missing flag --%s", sub.Name(), flag)
			}
		}
	}
}
