package measureutil

import "vSIS-Signature/measure"

// SnapshotAndReset returns the global measurement map and clears it.
func SnapshotAndReset() map[string]uint64 {
	return measure.Global.SnapshotAndReset()
}
