//go:build analysis

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
	sv "vSIS-Signature/ntru/signverify"

	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
)

type summaryStats struct {
	Count    int     `json:"count"`
	Mean     float64 `json:"mean"`
	Std      float64 `json:"std"`
	Min      float64 `json:"min"`
	Q1       float64 `json:"q1"`
	Median   float64 `json:"median"`
	Q3       float64 `json:"q3"`
	Max      float64 `json:"max"`
	IQR      float64 `json:"iqr"`
	Skewness float64 `json:"skewness"`
	Kurtosis float64 `json:"kurtosis_excess"`
}

// ------------------------------ stats utilities ------------------------------

func computeStats(x []float64) summaryStats {
	n := len(x)
	if n == 0 {
		return summaryStats{}
	}
	cp := append([]float64(nil), x...)
	sort.Float64s(cp)
	minv, maxv := cp[0], cp[n-1]
	median := quantileSorted(cp, 0.5)
	q1 := quantileSorted(cp, 0.25)
	q3 := quantileSorted(cp, 0.75)
	iqr := q3 - q1
	var m float64
	for _, v := range x {
		m += v
	}
	m /= float64(n)
	var m2, m3, m4 float64
	for _, v := range x {
		d := v - m
		d2 := d * d
		m2 += d2
		m3 += d2 * d
		m4 += d2 * d2
	}
	varVar := m2 / float64(n-1)
	std := math.Sqrt(varVar)
	var skew, kurtEx float64
	if std > 0 {
		m2n := m2 / float64(n)
		m3n := m3 / float64(n)
		m4n := m4 / float64(n)
		skew = m3n / math.Pow(m2n, 1.5)
		kurtEx = m4n/m2n/m2n - 3.0
	}
	return summaryStats{Count: n, Mean: m, Std: std, Min: minv, Q1: q1, Median: median, Q3: q3, Max: maxv, IQR: iqr, Skewness: skew, Kurtosis: kurtEx}
}

func quantileSorted(sorted []float64, p float64) float64 {
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	pos := p * float64(len(sorted)-1)
	l := int(math.Floor(pos))
	r := int(math.Ceil(pos))
	if l == r {
		return sorted[l]
	}
	w := pos - float64(l)
	return sorted[l]*(1-w) + sorted[r]*w
}

func freedmanDiaconisBins(x []float64) int {
	n := len(x)
	if n < 2 {
		return 1
	}
	cp := append([]float64(nil), x...)
	sort.Float64s(cp)
	iqr := quantileSorted(cp, 0.75) - quantileSorted(cp, 0.25)
	if iqr == 0 {
		if n < 200 {
			return n
		}
		return 200
	}
	bw := 2 * iqr * math.Pow(float64(n), -1.0/3.0)
	if bw <= 0 {
		if n < 200 {
			return n
		}
		return 200
	}
	r := cp[n-1] - cp[0]
	k := int(math.Ceil(r / bw))
	if k < 50 {
		k = 50
	}
	if k > 2000 {
		k = 2000
	}
	return k
}

func computeHistogram(values []float64, nbins int) (edges []float64, counts []int) {
	if len(values) == 0 {
		return []float64{0, 1}, []int{0}
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	minv, maxv := cp[0], cp[len(cp)-1]
	if nbins < 1 {
		nbins = 1
	}
	width := (maxv - minv) / float64(nbins)
	if width <= 0 {
		width = 1
	}
	edges = make([]float64, nbins+1)
	for i := 0; i <= nbins; i++ {
		edges[i] = minv + float64(i)*width
	}
	counts = make([]int, nbins)
	for _, v := range values {
		idx := int(math.Floor((v - minv) / width))
		if idx < 0 {
			idx = 0
		}
		if idx >= nbins {
			idx = nbins - 1
		}
		counts[idx]++
	}
	return
}

// ------------------------- collection helpers (JSON) -------------------------

func appendInt64(vals []float64, xs []int64) []float64 {
	for _, v := range xs {
		vals = append(vals, float64(v))
	}
	return vals
}

// read current keys in ./ntru_keys
func collectKeyCoeffs() (f, g, F, G, h []float64, err error) {
	pk, err := keys.LoadPublic()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sk, err := keys.LoadPrivate()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	f = appendInt64(nil, sk.Fsmall)
	g = appendInt64(nil, sk.Gsmall)
	F = appendInt64(nil, sk.F)
	G = appendInt64(nil, sk.G)
	h = appendInt64(nil, pk.HCoeffs)
	return
}

// read current signature if present
func collectSigCoeffs() (s0, s1, s2 []float64, ok bool) {
	sig, err := keys.Load()
	if err != nil || sig == nil {
		return nil, nil, nil, false
	}
	s0 = appendInt64(nil, sig.Signature.S0)
	s1 = appendInt64(nil, sig.Signature.S1)
	s2 = appendInt64(nil, sig.Signature.S2)
	return s0, s1, s2, true
}

// ------------------------- plotting: go-echarts HTML -------------------------

func toBarItems(vals []int) []opts.BarData {
	out := make([]opts.BarData, len(vals))
	for i, v := range vals {
		out[i] = opts.BarData{Value: v}
	}
	return out
}

func newHistogramChart(title string, values []float64, stats summaryStats) *charts.Bar {
	nbins := freedmanDiaconisBins(values)
	edges, counts := computeHistogram(values, nbins)
	xLabels := make([]string, nbins)
	for i := 0; i < nbins; i++ {
		center := 0.5 * (edges[i] + edges[i+1])
		xLabels[i] = fmt.Sprintf("%.2f", center)
	}
	bar := charts.NewBar()
	subtitle := fmt.Sprintf("n=%d, mean=%.3f, std=%.3f, median=%.3f, IQR=%.3f", stats.Count, stats.Mean, stats.Std, stats.Median, stats.IQR)
	bar.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: title, Subtitle: subtitle}),
		charts.WithInitializationOpts(opts.Initialization{PageTitle: title, Width: "1200px", Height: "600px"}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "inside"}, opts.DataZoom{Type: "slider"}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
	)
	bar.SetXAxis(xLabels).
		AddSeries("count", toBarItems(counts)).
		SetSeriesOptions(charts.WithLabelOpts(opts.Label{Show: opts.Bool(false)}))
	return bar
}

// ------------------------------ JSON and I/O ------------------------------

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ------------------------------- main routine -------------------------------

func main() {
	runs := flag.Int("runs", 20, "number of keygen runs")
	withSign := flag.Bool("sign", true, "also sign once per run and include s0/s1/s2")
	keygenMode := flag.String("keygen", "annulus", "keygen mode: annulus|cstyle")
	outDir := flag.String("out", "Measure_Reports", "output directory for reports")
	// Fixed-target options
	fixed := flag.Bool("fixed", false, "use fixed target across runs (fixed B,m,x0,x1)")
	bfile := flag.String("bfile", "Parameters/Bmatrix.json", "B-matrix file for target hashing (fixed mode)")
	mstr := flag.String("m", "analysis-fixed", "message string (fixed mode; hashed with SHA256)")
	mseedHex := flag.String("mseedhex", "", "optional 32-byte hex message seed (overrides -m)")
	x0hex := flag.String("x0hex", "", "optional 32-byte hex x0 seed (fixed mode)")
	x1hex := flag.String("x1hex", "", "optional 32-byte hex x1 seed (fixed mode)")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	// Prepare accumulators
	var allF, allG, allFbig, allGbig, allH []float64
	var allS0, allS1, allS2 []float64

	// Load system params (N/Q from Parameters/Parameters.json)
	sys, err := sv.LoadParamsForCLI()
	if err != nil {
		log.Fatalf("load params: %v", err)
	}
	par, err := ntru.NewParams(sys.N, new(big.Int).SetUint64(sys.Q))
	if err != nil {
		log.Fatalf("params: %v", err)
	}

	// For keygen (re-use CLI defaults)
	mode := strings.ToLower(*keygenMode)
	if mode == "" || mode == "auto" {
		mode = "annulus"
	}
	if mode != "annulus" {
		log.Fatalf("unsupported keygen mode %q (only annulus)", mode)
	}
	attemptKeygen := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("keygen panic: %v", r)
			}
		}()
		_, _, err = sv.GenerateKeypairAnnulus(par, ntru.KeygenOpts{Prec: 256, MaxTrials: 10000, Alpha: 1.20})
		return err
	}
	for i := 0; i < *runs; i++ {
		attempts := 0
		for {
			attempts++
			log.Printf("[analysis] run %d/%d (attempt %d)", i+1, *runs, attempts)
			if err := attemptKeygen(); err != nil {
				log.Printf("warn: keygen attempt %d failed: %v", attempts, err)
				continue
			}
			break
		}

		f, g, F, G, h, err := collectKeyCoeffs()
		if err != nil {
			log.Fatalf("collect keys: %v", err)
		}
		allF = append(allF, f...)
		allG = append(allG, g...)
		allFbig = append(allFbig, F...)
		allGbig = append(allGbig, G...)
		allH = append(allH, h...)

		if *withSign {
			if *fixed {
				// Build fixed seeds
				var mSeed []byte
				if *mseedHex != "" {
					b, err := hex.DecodeString(strings.TrimPrefix(*mseedHex, "0x"))
					if err != nil {
						log.Fatalf("mseedhex: %v", err)
					}
					mSeed = b
				} else {
					sum := sha256.Sum256([]byte(*mstr))
					mSeed = sum[:]
				}
				var x0Seed, x1Seed []byte
				if *x0hex != "" {
					b, err := hex.DecodeString(strings.TrimPrefix(*x0hex, "0x"))
					if err != nil {
						log.Fatalf("x0hex: %v", err)
					}
					x0Seed = b
				} else {
					sum := sha256.Sum256([]byte("x0|" + *mstr))
					x0Seed = sum[:]
				}
				if *x1hex != "" {
					b, err := hex.DecodeString(strings.TrimPrefix(*x1hex, "0x"))
					if err != nil {
						log.Fatalf("x1hex: %v", err)
					}
					x1Seed = b
				} else {
					sum := sha256.Sum256([]byte("x1|" + *mstr))
					x1Seed = sum[:]
				}
				// Compute target and sample using current key
				tCoeffs, err := ntru.ComputeTargetFromSeeds(sys, *bfile, mSeed, x0Seed, x1Seed)
				if err != nil {
					log.Fatalf("ComputeTargetFromSeeds: %v", err)
				}
				priv, err := keys.LoadPrivate()
				if err != nil {
					log.Fatalf("load private: %v", err)
				}
				S, err := ntru.NewSampler(priv.Fsmall, priv.Gsmall, priv.F, priv.G, par, 256)
				if err != nil {
					log.Fatalf("NewSampler: %v", err)
				}
				S.Opts = ntru.SamplerOpts{RSquare: 7.84, Alpha: 1.25, Slack: 1e4, MaxSignTrials: 2048, ReduceIters: 64, UseCNormalDist: true} //Rsquare was 2.0
				if err := S.BuildGram(); err != nil {
					log.Fatalf("BuildGram: %v", err)
				}
				tPoly := ntru.Int64ToModQPoly(tCoeffs, par)
				s0, s1, _, err := S.SamplePreimageTargetOptionB(tPoly, 2048)
				if err != nil {
					log.Fatalf("OptionB: %v", err)
				}
				allS0 = appendInt64(allS0, coeffToI64(s0))
				allS1 = appendInt64(allS1, coeffToI64(s1))
				if s2 := S.LastS2(); len(s2) > 0 {
					allS2 = appendInt64(allS2, s2)
				}
			} else {
				msg := fmt.Sprintf("analysis-%d", i)
				if _, err := sv.Sign([]byte(msg), 2048); err != nil {
					log.Fatalf("sign: %v", err)
				}
				if s0, s1, s2, ok := collectSigCoeffs(); ok {
					allS0 = append(allS0, s0...)
					allS1 = append(allS1, s1...)
					allS2 = append(allS2, s2...)
				}
			}
		}
	}

	// Compute stats
	outStats := map[string]summaryStats{
		"f": computeStats(allF),
		"g": computeStats(allG),
		"F": computeStats(allFbig),
		"G": computeStats(allGbig),
		"h": computeStats(allH),
	}
	if len(allS0) > 0 {
		outStats["s0"] = computeStats(allS0)
	}
	if len(allS1) > 0 {
		outStats["s1"] = computeStats(allS1)
	}
	if len(allS2) > 0 {
		outStats["s2"] = computeStats(allS2)
	}

	ts := time.Now().Format("20060102_150405")
	jsonPath := filepath.Join(*outDir, fmt.Sprintf("coeff_stats_%s.json", ts))
	if err := saveJSON(jsonPath, outStats); err != nil {
		log.Printf("warn: save stats: %v", err)
	}

	// Build a single HTML page with multiple histograms
	page := components.NewPage()

	add := func(name string, vals []float64) {
		if len(vals) == 0 {
			return
		}
		st := computeStats(vals)
		page.AddCharts(newHistogramChart(name, vals, st))
	}
	add("f (private small)", allF)
	add("g (private small)", allG)
	add("F (private)", allFbig)
	add("G (private)", allGbig)
	add("h (public)", allH)
	add("s0 (signature)", allS0)
	add("s1 (signature)", allS1)
	add("s2 (centered residual)", allS2)

	htmlPath := filepath.Join(*outDir, fmt.Sprintf("coeff_histograms_%s.html", ts))
	f, err := os.Create(htmlPath)
	if err != nil {
		log.Fatalf("create html: %v", err)
	}
	defer f.Close()
	if err := page.Render(f); err != nil {
		log.Fatalf("render html: %v", err)
	}
	fmt.Println("Histogram page:", htmlPath)
	fmt.Println("Stats JSON:", jsonPath)
}

// (helpers)
func coeffToI64(p *ntru.CoeffPoly) []int64 {
	out := make([]int64, len(p.Coeffs))
	for i := range p.Coeffs {
		out[i] = p.Coeffs[i].Int64()
	}
	return out
}
