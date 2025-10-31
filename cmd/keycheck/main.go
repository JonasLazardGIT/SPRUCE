package main

import (
	"fmt"
	"log"
	"math/big"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
)

func maxAbs(vals []int64) int64 {
	var m int64
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

func main() {
	sig, err := keys.Load()
	if err != nil {
		log.Fatalf("load signature: %v", err)
	}
	priv, err := keys.LoadPrivate()
	if err != nil {
		log.Fatalf("load private: %v", err)
	}
	qInt := new(big.Int)
	if _, ok := qInt.SetString(sig.Params.Q, 16); !ok {
		log.Fatalf("invalid Q hex: %s", sig.Params.Q)
	}
	par, err := ntru.NewParams(sig.Params.N, qInt)
	if err != nil {
		log.Fatalf("params: %v", err)
	}

	h, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(priv.Fsmall, par), ntru.Int64ToModQPoly(priv.Gsmall, par), par)
	if err != nil {
		log.Fatalf("PublicKeyH: %v", err)
	}
	s1 := ntru.Int64ToModQPoly(sig.Signature.S1, par)
	hs1, err := ntru.ConvolveRNS(s1, h, par)
	if err != nil {
		log.Fatalf("ConvolveRNS: %v", err)
	}
	tPoly := ntru.Int64ToModQPoly(sig.Hash.TCoeffs, par)
	residual := hs1.Add(tPoly)
	center, err := ntru.CenterModQToInt64(residual, par)
	if err != nil {
		log.Fatalf("center residual: %v", err)
	}
	fmt.Println("Residual Linf:", maxAbs(center))
	fmt.Println("Residual first 16:", center[:min(16, len(center))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
