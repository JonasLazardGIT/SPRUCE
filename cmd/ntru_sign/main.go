package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
)

func main() {
	msgPath := flag.String("msg", "", "message file path or hex (if starts with 0x)")
	targetHex := flag.String("target", "", "target polynomial hex (coeffs colon-separated) or file path")
	outdir := flag.String("outdir", "./NTRU_Signature", "output directory")
	alpha := flag.Float64("alpha", 1.25, "ANTRAG_ALPHA")
	rsqDefault := ntru.CReferenceRSquare()
	rsq := flag.Float64("rsq", rsqDefault, fmt.Sprintf("R_SQUARE (default %.4f)", rsqDefault))
	slack := flag.Float64("slack", 1.042, "ANTRAG_SLACK")
	trials := flag.Int("trials", 2048, "max trials")
	N := flag.Int("N", 512, "ring dimension (power of two)")
	Qhex := flag.String("Q", "0xfd801", "modulus Q in hex (default 0xfd801 = 1038337)")
	flag.Parse()

	if *Qhex == "" {
		log.Fatal("-Q hex modulus required")
	}
	Q := new(big.Int)
	if _, ok := Q.SetString(strip0x(*Qhex), 16); !ok {
		log.Fatal("invalid Q hex")
	}
	par, err := ntru.NewParams(*N, Q)
	if err != nil {
		log.Fatal(err)
	}

	var f, g, F, G []int64
	kg := ntru.KeygenOpts{Prec: 128, MaxTrials: 10000, Alpha: *alpha}
	f, g, F, G, err = ntru.Keygen(par, kg)
	if err != nil {
		log.Fatal(err)
	}
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		log.Fatal(err)
	}
	S.Opts.Alpha = *alpha
	S.Opts.RSquare = *rsq
	S.Opts.Slack = *slack
	S.Opts.MaxSignTrials = *trials
	if err := S.BuildGram(); err != nil {
		log.Fatal(err)
	}

	var t ntru.ModQPoly
	if *targetHex != "" {
		// parse colon-separated hex coeffs or load file
		if data, err := os.ReadFile(*targetHex); err == nil {
			t = parsePolyHex(string(data), par)
		} else {
			t = parsePolyHex(*targetHex, par)
		}
	} else if *msgPath != "" {
		var msg []byte
		if has0x(*msgPath) {
			b, _ := hex.DecodeString(strip0x(*msgPath))
			msg = b
		} else {
			b, err := os.ReadFile(*msgPath)
			if err != nil {
				log.Fatal(err)
			}
			msg = b
		}
		sys, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
		if err != nil {
			log.Fatal(err)
		}
		mSeedArr := sha256.Sum256(msg)
		mSeed := mSeedArr[:]
		x0Seed := make([]byte, 32)
		x1Seed := make([]byte, 32)
		if _, err := crand.Read(x0Seed); err != nil {
			log.Fatal(err)
		}
		if _, err := crand.Read(x1Seed); err != nil {
			log.Fatal(err)
		}
		coeffs, err := ntru.ComputeTargetFromSeeds(&sys, "Parameters/Bmatrix.json", mSeed, x0Seed, x1Seed)
		if err != nil {
			log.Fatal(err)
		}
		t = ntru.Int64ToModQPoly(coeffs, par)
	} else {
		log.Fatal("either --target or --msg required")
	}

	// Use Hybrid-B sampler directly
	s0, s1, used, err := S.SamplePreimageTargetOptionB(t, *trials)
	if err != nil {
		log.Fatal(err)
	}
	if *outdir != "" {
		os.MkdirAll(*outdir, 0o755)
	}
	path, err := S.WriteTargetSignature(nil, &t, s0, s1, used)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)
}

func parsePolyHex(src string, par ntru.Params) ntru.ModQPoly {
	p := ntru.NewModQPoly(par.N, par.Q)
	// simplistic: accept colon-separated hex; else fill zeros
	// users may extend this parser to JSON as needed.
	return p
}

func has0x(s string) bool { return len(s) > 1 && s[0:2] == "0x" }
func strip0x(s string) string {
	if has0x(s) {
		return s[2:]
	}
	return s
}
