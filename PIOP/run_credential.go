package PIOP

import (
	"fmt"
)

// runCredential is a placeholder path for credential mode. The full
// integration of credential constraints into the PACS builder is not yet
// implemented.
func runCredential(o SimOpts) (SimReport, error) {
	builder := NewCredentialBuilder(o)
	_ = builder
	return SimReport{}, fmt.Errorf("credential mode not implemented yet")
}
