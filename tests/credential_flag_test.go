package tests

import (
	"testing"

	PIOP "vSIS-Signature/PIOP"
)

// Ensure the Credential flag can be set without panicking and defaults remain stable.
func TestSimOptsCredentialFlag(t *testing.T) {
	opts := PIOP.SimOpts{Credential: true}
	opts.ApplyDefaultsExported()
	if !opts.Credential {
		t.Fatalf("credential flag lost after ApplyDefaults")
	}
}
