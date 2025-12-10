package tests

import (
	"testing"

	PIOP "vSIS-Signature/PIOP"
)

func TestBuildPublicLabelsOrder(t *testing.T) {
	labels := PIOP.BuildPublicLabels(PIOP.PublicInputs{})
	if labels != nil && len(labels) != 0 {
		t.Fatalf("expected empty labels on empty inputs, got %d", len(labels))
	}
}
