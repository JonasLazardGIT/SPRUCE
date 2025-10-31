package tests

import (
    "math/big"
    "os"
    "testing"
    ntru "vSIS-Signature/ntru"
)

// This test exercises the LOG3_D path by enabling the flag and verifying the
// solver maintains the identity on tiny N (even though N is power-of-two here).
func TestTower_LOG3D_Deg2_Path(t *testing.T) {
    if os.Getenv("NTRU_LOG3") != "1" {
        t.Skip("set NTRU_LOG3=1 to enable LOG3_D small-N test")
    }
    par, _ := ntru.NewParams(2, big.NewInt(12289))
    par.LOG3_D = true
    par.M = 6
    f := []int64{1, 2}
    g := []int64{1, -1}
    F, G, err := ntru.NTRUSolve(f, g, par, ntru.SolveOpts{Prec: 128, Reduce: false})
    if err != nil {
        t.Fatalf("NTRUSolve(LOG3 deg2): %v", err)
    }
    if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
        t.Fatalf("identity failed in LOG3 deg2 case")
    }
}
