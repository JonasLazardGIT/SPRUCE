package ntru

import (
    "math/big"
)

// extGCDCanon returns (u,v,g) such that a*u + b*v = g = gcd(a,b) with a canonicalized
// choice intended to mimic GMP's mpz_gcdext on small integers, and to be stable
// across platforms. We minimize |v| by shifting along the solution lattice, and in
// a tie we prefer a negative v. If v would be 0 (degenerate for our basecase usage
// where F0 := v*Q), we shift once more to obtain a non-zero v of minimal magnitude.
func extGCDCanon(a, b *big.Int) (u, v, g *big.Int) {
    // Compute one extended gcd solution
    u0 := new(big.Int)
    v0 := new(big.Int)
    g0 := new(big.Int).GCD(u0, v0, a, b) // a*u0 + b*v0 = g0

    // If either a or b is zero, return the trivial canonical form.
    if a.Sign() == 0 {
        // gcd = |b|; pick u=0, v=sign(b)
        v = new(big.Int).SetInt64(1)
        if b.Sign() < 0 { v.Neg(v) }
        u = new(big.Int)
        g = new(big.Int).Abs(b)
        return
    }
    if b.Sign() == 0 {
        // gcd = |a|; pick u=sign(a), v=0
        u = new(big.Int).SetInt64(1)
        if a.Sign() < 0 { u.Neg(u) }
        v = new(big.Int)
        g = new(big.Int).Abs(a)
        return
    }

    // Shift (u0,v0) by k to minimize |v| where (u,v) = (u0 + k*b, v0 - k*a)
    // Choose k = round(v0 / a).
    k := new(big.Int)
    // Compute v0/a as a rational and round to nearest integer.
    // Implement round(v0/a) as floor((v0 + sign(a)*a/2)/a).
    halfA := new(big.Int).Abs(a)
    halfA.Rsh(halfA, 1) // floor(|a|/2)
    num := new(big.Int).Set(v0)
    if a.Sign() > 0 {
        num.Add(num, halfA)
    } else {
        num.Sub(num, halfA)
    }
    k.Quo(num, a) // floor division toward -Inf for negative a in Go is toward zero; using Quo for trunc toward zero; acceptable with above adjustment

    // Apply the shift
    u = new(big.Int).Add(u0, new(big.Int).Mul(k, b))
    v = new(big.Int).Sub(v0, new(big.Int).Mul(k, a))

    // If |v| can be reduced by moving one step in either direction, pick the smaller.
    vAbs := new(big.Int).Abs(v)
    // Try k+1
    v1 := new(big.Int).Sub(v0, new(big.Int).Mul(new(big.Int).Add(k, big.NewInt(1)), a))
    if new(big.Int).Abs(v1).Cmp(vAbs) < 0 {
        k.Add(k, big.NewInt(1))
        u.Add(u0, new(big.Int).Mul(k, b))
        v.Set(v1)
        vAbs.Set(new(big.Int).Abs(v))
    } else {
        // Try k-1
        v2 := new(big.Int).Sub(v0, new(big.Int).Mul(new(big.Int).Sub(k, big.NewInt(1)), a))
        if new(big.Int).Abs(v2).Cmp(vAbs) < 0 {
            k.Sub(k, big.NewInt(1))
            u.Add(u0, new(big.Int).Mul(k, b))
            v.Set(v2)
            vAbs.Set(new(big.Int).Abs(v))
        }
    }

    // Tie-break: prefer negative v if |v| is tied between +t and -t.
    if v.Sign() == 0 {
        // avoid degenerate v=0 by shifting one step toward negative v
        step := big.NewInt(1)
        if a.Sign() < 0 { step.Neg(step) }
        k.Add(k, step)
        u.Add(u0, new(big.Int).Mul(k, b))
        v.Sub(v0, new(big.Int).Mul(k, a))
    } else {
        // If v>0, check v' = v - sign(v)*a for tie with same magnitude but negative
        alt := new(big.Int).Sub(v, a)
        if v.Sign() > 0 && new(big.Int).Abs(alt).Cmp(vAbs) == 0 && alt.Sign() < 0 {
            // shift by +1 to flip sign without changing |v|
            k.Add(k, big.NewInt(1))
            u.Add(u0, new(big.Int).Mul(k, b))
            v.Set(alt)
        }
    }

    g = g0
    return
}

