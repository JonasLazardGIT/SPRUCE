package ntru

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
)

var (
	cSmoothingOnce sync.Once
	cSmoothingVal  float64
	cSmoothingErr  error
)

const defaultCSmoothing = 1.32

func CReferenceSmoothing() float64 {
	cSmoothingOnce.Do(func() {
		cSmoothingVal, cSmoothingErr = detectCSmoothing()
		if cSmoothingErr != nil || cSmoothingVal <= 0 {
			cSmoothingVal = defaultCSmoothing
		}
	})
	return cSmoothingVal
}

func CReferenceRSquare() float64 {
	s := CReferenceSmoothing()
	return s * s
}

type systemParams struct {
	N int    `json:"n"`
	Q uint64 `json:"q"`
}

func detectCSmoothing() (float64, error) {
	if sp, err := loadSystemParams(); err == nil {
		const maxCReferenceQ = (1 << 16) - 1
		if sp.Q > maxCReferenceQ {
			return 0, fmt.Errorf("c smoothing parameter unavailable for q=%d (n=%d exceeds C reference range)", sp.Q, sp.N)
		}
	}
	return detectCSmoothingFromC()
}

func detectCSmoothingFromC() (float64, error) {
	type candidate struct {
		path  string
		regex *regexp.Regexp
	}
	candidates := []candidate{
		{
			path:  filepath.Join("ntru_c", "antrag_opt-main", "gen", "const.h"),
			regex: regexp.MustCompile(`(?m)^#define\s+R\s+([0-9]+(?:\.[0-9]+)?)`),
		},
		{
			path:  filepath.Join("ntru_c", "antrag_opt-main", "scripts", "gen_headers.sage"),
			regex: regexp.MustCompile(`(?m)smoothing\s*=\s*([0-9]+(?:\.[0-9]+)?)`),
		},
	}
	for _, cand := range candidates {
		if val, err := parseFloatFromFile(cand.path, cand.regex); err == nil {
			return val, nil
		}
	}
	return 0, errors.New("c smoothing parameter not found")
}

func loadSystemParams() (systemParams, error) {
	path := filepath.Join("Parameters", "Parameters.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return systemParams{}, err
	}
	var sp systemParams
	if err := json.Unmarshal(data, &sp); err != nil {
		return systemParams{}, err
	}
	if sp.N <= 0 || sp.Q == 0 {
		return systemParams{}, errors.New("invalid system parameters")
	}
	return sp, nil
}

func parseFloatFromFile(path string, re *regexp.Regexp) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			val, err := strconv.ParseFloat(matches[1], 64)
			if err != nil {
				return 0, err
			}
			if math.IsNaN(val) || math.IsInf(val, 0) {
				return 0, errors.New("invalid smoothing value")
			}
			return val, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("pattern not found")
}
