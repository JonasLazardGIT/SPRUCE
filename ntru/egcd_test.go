package ntru

import (
    "math/big"
    "testing"
)

func TestExtGCDCanon_Small(t *testing.T) {
    a := big.NewInt(1)
    b := big.NewInt(-1)
    u, v, g := extGCDCanon(a, b)
    if g.Cmp(big.NewInt(1)) != 0 {
        t.Fatalf("gcd != 1: %s", g.String())
    }
    // Expect a*u + b*v = 1
    lhs := new(big.Int).Add(new(big.Int).Mul(a, u), new(big.Int).Mul(b, v))
    if lhs.Cmp(big.NewInt(1)) != 0 {
        t.Fatalf("Bezout failed: %s", lhs.String())
    }
    // Canonicalize such that v is small, negative, and non-zero for this case.
    if v.Cmp(big.NewInt(-1)) != 0 {
        t.Fatalf("unexpected v: got %s want -1", v.String())
    }
}

