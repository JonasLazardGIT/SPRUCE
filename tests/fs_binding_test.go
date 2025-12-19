package tests

import (
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
	PIOP "vSIS-Signature/PIOP"
)

func TestBuildPublicLabelsOrder(t *testing.T) {
	r, err := ring.NewRing(16, []uint64{65537})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	p := r.NewPoly()
	p.Coeffs[0][0] = 1
	pub := PIOP.PublicInputs{
		Com:    []*ring.Poly{p},
		RI0:    []*ring.Poly{p},
		RI1:    []*ring.Poly{p},
		Ac:     [][]*ring.Poly{{p}},
		B:      []*ring.Poly{p},
		Extras: map[string]interface{}{"X": []byte{0x01}},
	}
	labels := PIOP.BuildPublicLabels(pub)
	if len(labels) < 5 {
		t.Fatalf("expected at least 5 labels, got %d", len(labels))
	}
	if labels[0].Name != "Com" {
		t.Fatalf("expected Com first, got %s", labels[0].Name)
	}
}

func TestBuildPublicLabelsEmpty(t *testing.T) {
	labels := PIOP.BuildPublicLabels(PIOP.PublicInputs{})
	if len(labels) != 0 {
		t.Fatalf("expected no labels, got %d", len(labels))
	}
}
