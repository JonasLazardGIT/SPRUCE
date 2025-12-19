package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// validatePublics enforces the single-poly convention and shape checks for credential mode.
func validatePublics(pub PublicInputs) error {
	// Single-poly requirement: if provided, each slice length must be 1 (Com/Ac can be multi-row).
	checkOne := func(name string, v []*ring.Poly) error {
		if len(v) == 0 {
			return nil
		}
		if len(v) != 1 {
			return fmt.Errorf("%s: expected 1 poly, got %d", name, len(v))
		}
		if v[0] == nil {
			return fmt.Errorf("%s: nil poly", name)
		}
		return nil
	}
	if err := checkOne("RI0", pub.RI0); err != nil {
		return err
	}
	if err := checkOne("RI1", pub.RI1); err != nil {
		return err
	}
	// B may contain 4 polynomials (B0..B3) for the hash gadget.
	if len(pub.B) != 0 && len(pub.B) != 1 && len(pub.B) != 4 {
		return fmt.Errorf("b: expected 1 or 4 polys, got %d", len(pub.B))
	}
	// BoundB is only required when running credential mode; builders enforce >0 when needed.
	// Com and Ac can have multiple rows; ensure consistent shape if present.
	if len(pub.Ac) > 0 {
		rowLen := len(pub.Ac[0])
		if rowLen == 0 {
			return fmt.Errorf("ac: empty first row")
		}
		for i, row := range pub.Ac {
			if len(row) != rowLen {
				return fmt.Errorf("ac: ragged row %d", i)
			}
		}
		if len(pub.Com) > 0 && len(pub.Com) != len(pub.Ac) {
			return fmt.Errorf("com length %d mismatches ac rows %d", len(pub.Com), len(pub.Ac))
		}
	}
	return nil
}

// validateWitnesses enforces single-poly blocks for credential mode.
func validateWitnesses(wit WitnessInputs) error {
	checkOne := func(name string, v []*ring.Poly) error {
		if len(v) != 1 {
			return fmt.Errorf("%s: expected 1 poly, got %d", name, len(v))
		}
		if v[0] == nil {
			return fmt.Errorf("%s: nil poly", name)
		}
		return nil
	}
	if err := checkOne("M1", wit.M1); err != nil {
		return err
	}
	if err := checkOne("M2", wit.M2); err != nil {
		return err
	}
	if err := checkOne("RU0", wit.RU0); err != nil {
		return err
	}
	if err := checkOne("RU1", wit.RU1); err != nil {
		return err
	}
	if err := checkOne("R", wit.R); err != nil {
		return err
	}
	if len(wit.R0) > 0 {
		if err := checkOne("R0", wit.R0); err != nil {
			return err
		}
	}
	if len(wit.R1) > 0 {
		if err := checkOne("R1", wit.R1); err != nil {
			return err
		}
	}
	// If the centered randomness rows are provided, require the corresponding
	// carry rows (paper-faithful center wrap uses RU+RI = R + (2B+1)·K).
	if len(wit.R0) > 0 || len(wit.R1) > 0 {
		if err := checkOne("K0", wit.K0); err != nil {
			return err
		}
		if err := checkOne("K1", wit.K1); err != nil {
			return err
		}
	}
	return nil
}
