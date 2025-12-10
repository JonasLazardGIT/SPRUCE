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

// Ensure credential path returns a clear error for now.
func TestRunOnceCredentialStub(t *testing.T) {
	_, err := PIOP.RunOnce(PIOP.SimOpts{Credential: true})
	if err == nil {
		t.Fatalf("expected error for credential mode")
	}
}
