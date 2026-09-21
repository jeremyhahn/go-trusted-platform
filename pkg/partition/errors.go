package partition

import "strings"

// NotAPartitionError reports a device path that does not end in a partition
// number, so no parent disk can be derived from it.
type NotAPartitionError struct {
	Path string
}

// Error implements error.
func (e *NotAPartitionError) Error() string {
	return "partition: " + e.Path + " is not a partition path"
}

// ESPNotFoundError reports that no EFI system partition could be found for a
// root device. Tried lists every path that was probed, in order.
type ESPNotFoundError struct {
	RootDevice string
	Tried      []string
}

// Error implements error.
func (e *ESPNotFoundError) Error() string {
	return "partition: no EFI system partition found for root device " + e.RootDevice +
		" (tried " + strings.Join(e.Tried, ", ") + ")"
}
