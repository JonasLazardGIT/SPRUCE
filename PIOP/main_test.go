package PIOP

import (
	"os"
	"testing"
	measure "vSIS-Signature/measure"
)

// TestMain runs all tests and, if size measurement is enabled,
// dumps a consolidated size report to file at the end.
func TestMain(m *testing.M) {
	code := m.Run()
	if measure.Enabled {
		measure.Global.Dump()
	}
	os.Exit(code)
}
