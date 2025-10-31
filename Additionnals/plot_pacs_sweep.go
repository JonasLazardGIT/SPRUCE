package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
)

type OptsStruct struct {
	Rho        int   `json:"Rho"`
	EllPrime   int   `json:"EllPrime"`
	Ell        int   `json:"Ell"`
	Eta        int   `json:"Eta"`
	NLeaves    int   `json:"NLeaves"`
	Theta      int   `json:"Theta"`
	Kappa      []int `json:"Kappa"`
	NCols      int   `json:"NCols"`
	DQOverride int   `json:"DQOverride"`
	Lambda     int   `json:"Lambda"`
	ChainW     int   `json:"ChainW"`
	ChainL     int   `json:"ChainL"`
}

type SoundnessStruct struct {
	Eps          []float64 `json:"Eps"`
	Bits         []float64 `json:"Bits"`
	Grinding     []float64 `json:"Grinding"`
	GrindingBits []float64 `json:"GrindingBits"`
	Total        float64   `json:"Total"`
	TotalBits    float64   `json:"TotalBits"`
	DQ           int       `json:"DQ"`
	NRows        int       `json:"NRows"`
	M            int       `json:"M"`
}

type VerdictStruct struct {
	OkLin bool `json:"OkLin"`
	OkEq4 bool `json:"OkEq4"`
	OkSum bool `json:"OkSum"`
}

type SweepRow struct {
	Stage           string           `json:"-"`
	Opts            OptsStruct       `json:"Opts"`
	Soundness       SoundnessStruct  `json:"Soundness"`
	Verdict         VerdictStruct    `json:"Verdict"`
	ProofBytes      int              `json:"ProofBytes"`
	ProofSizeLayers map[string]int   `json:"ProofSizeLayers"`
	SizesB          map[string]int   `json:"SizesB"`
	Degree          int              `json:"Degree"`
	TimingsUS       map[string]int64 `json:"TimingsUS"`
}

type sweepRecord struct {
	Stage  string   `json:"stage"`
	Report SweepRow `json:"report"`
}

type point struct {
	totalBits float64
	proofKB   float64
	timeMS    float64
	val       []interface{} // payload for tooltip
}

func reportTopParameterSets(rows []SweepRow, source string, minBitsFlag float64) {
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "no sweep rows to summarize for %s\n", source)
		return
	}

	type candidate struct {
		row     SweepRow
		score   float64
		proofKB float64
		timeSec float64
	}

	securityBitsThreshold := minBitsFlag
	if securityBitsThreshold <= -math.MaxFloat64/2 {
		securityBitsThreshold = 132.0
	}
	if securityBitsThreshold < 0 {
		securityBitsThreshold = 0
	}

	bestByKey := make(map[string]candidate)
	for _, r := range rows {
		if r.Soundness.TotalBits <= securityBitsThreshold {
			continue
		}

		proofKB := float64(r.ProofBytes) / 1024.0
		timeSec := 0.0
		if r.TimingsUS != nil {
			if total, ok := r.TimingsUS["__total__"]; ok {
				timeSec = float64(total) / 1_000_000.0
			}
		}
		score := 0.06*proofKB + (1.2 * timeSec)

		key := fmt.Sprintf("%d|%d|%d|%d", r.Opts.NCols, r.Opts.Ell, r.Opts.EllPrime, r.Opts.Rho)
		if existing, ok := bestByKey[key]; !ok || score < existing.score {
			bestByKey[key] = candidate{
				row:     r,
				score:   score,
				proofKB: proofKB,
				timeSec: timeSec,
			}
		}
	}

	if len(bestByKey) == 0 {
		fmt.Printf("No parameter sets with security parameter ≥ %.2f bits found in %s\n", securityBitsThreshold, source)
		return
	}

	candidates := make([]candidate, 0, len(bestByKey))
	for _, c := range bestByKey {
		candidates = append(candidates, c)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		if candidates[i].timeSec != candidates[j].timeSec {
			return candidates[i].timeSec < candidates[j].timeSec
		}
		if candidates[i].proofKB != candidates[j].proofKB {
			return candidates[i].proofKB < candidates[j].proofKB
		}
		return candidates[i].row.Soundness.TotalBits > candidates[j].row.Soundness.TotalBits
	})

	limit := 10
	if len(candidates) < limit {
		limit = len(candidates)
	}

	fmt.Printf("Top %d parameter sets by score (sizeKB + 1.2*timeSec) from %s\n", limit, source)
	fmt.Println("Rank | Score   | ProofKB | Time(s) | Bits  | NCols | Ell | Ell' | Rho | Theta | Eta | Degree | W")
	for i := 0; i < limit; i++ {
		c := candidates[i]
		r := c.row
		fmt.Printf(
			"%2d)  %7.3f & %7.2f & %7.3f & %6.2f & %5d & %3d & %4d & %3d & %5d & %3d & %6d & %6d \\ \n",
			i+1,
			c.score,
			c.proofKB,
			c.timeSec,
			r.Soundness.TotalBits,
			r.Opts.NCols,
			r.Opts.Ell,
			r.Opts.EllPrime,
			r.Opts.Rho,
			r.Opts.Theta,
			r.Opts.Eta,
			r.Degree,
			r.Opts.ChainW,
		)
	}
}

// injectFilterUI adds client-side sliders to filter scatter series.
func injectFilterUI(sc *charts.Scatter) {
	js := `(function(){
  var chart = %MY_ECHARTS%;
  if(!chart) return;
  var dom = chart.getDom();
  if(!dom || !dom.id) return;
  var panelId = dom.id + '_filter_panel';
  if(document.getElementById(panelId)) return;

  function unwrap(list){ return (list||[]).map(d => (d && d.value !== undefined) ? d.value : d); }

  var opt   = chart.getOption();
  var series = opt && opt.series ? opt.series : [];
  var allLF = series[0] && series[0].data ? unwrap(series[0].data) : [];
  var allSF = series[1] && series[1].data ? unwrap(series[1].data) : [];
  var both  = allLF.concat(allSF);

  var dims = {bits:0, kb:1, ms:2, theta:3, rho:4, ellp:5, ncols:7, eta:8, chainW:14, chainL:15};

  function minmax(data, idx){
    var lo = Infinity, hi = -Infinity;
    data.forEach(function(v){
      if(!v) return;
      var x = v[idx];
      if(x < lo) lo = x;
      if(x > hi) hi = x;
    });
    if(!isFinite(lo)) lo = 0;
    if(!isFinite(hi)) hi = 0;
    return [lo, hi];
  }

  var ranges = {
    ms:     minmax(both, dims.ms),
    rho:    minmax(both, dims.rho),
    ellp:   minmax(both, dims.ellp),
    eta:    minmax(both, dims.eta),
    theta:  minmax(both, dims.theta),
    ncols:  minmax(both, dims.ncols),
    chainW: minmax(both, dims.chainW),
    chainL: minmax(both, dims.chainL)
  };

  var prefix = dom.id + '_';

  function createSlider(label, key, step){
    var wrap = document.createElement('div');
    wrap.style.cssText='margin:6px 10px;';
    var idL=prefix+'lbl_'+key, id0=prefix+'min_'+key, id1=prefix+'max_'+key;
    var min=ranges[key][0], max=ranges[key][1];
    var s = step || 1;
    wrap.innerHTML =
      '<div style="font:12px sans-serif;margin-bottom:2px;"><b>'+label+
      '</b> <span id="'+idL+'">['+min+'…'+max+']</span></div>'+
      '<input id="'+id0+'" type="range" min="'+min+'" max="'+max+'" step="'+s+'" value="'+min+'" style="width:48%;margin-right:2%;">'+
      '<input id="'+id1+'" type="range" min="'+min+'" max="'+max+'" step="'+s+'" value="'+max+'" style="width:48%;">';
    return {wrap:wrap, ids:[id0,id1,idL]};
  }

  var panel = document.createElement('div');
  panel.id = panelId;
  panel.style.cssText='border:1px solid #ddd;border-radius:8px;padding:10px;margin:10px 0;background:#fafafa;';
  var title = document.createElement('div');
  title.innerHTML = '<b>Filters</b> · drag sliders to filter visible points';
  title.style.cssText='font:14px/1.3 sans-serif;margin-bottom:6px;';
  panel.appendChild(title);

  var S = {
    ms:     createSlider('Time (ms)','ms', 1),
    rho:    createSlider('ρ','rho', 1),
    ellp:   createSlider('ℓ′','ellp', 1),
    eta:    createSlider('η','eta', 1),
    theta:  createSlider('θ','theta', 1),
    ncols:  createSlider('ncols','ncols', 1),
    chainW: createSlider('chain W','chainW', 1),
    chainL: createSlider('chain L','chainL', 1)
  };
  Object.keys(S).forEach(function(k){ panel.appendChild(S[k].wrap); });

  var stats = document.createElement('div');
  stats.id = prefix + 'stats';
  stats.style.cssText='font:12px sans-serif;opacity:.8;margin-top:6px;';
  panel.appendChild(stats);

  var parent = dom.parentNode;
  if(!parent) return;
  parent.insertBefore(panel, dom);

  function elem(id){ return document.getElementById(id); }

  function readRange(key){
    var a = +elem(prefix+'min_'+key).value;
    var b = +elem(prefix+'max_'+key).value;
    if(a > b){ var t = a; a = b; b = t; }
    elem(prefix+'lbl_'+key).textContent = '['+a+'…'+b+']';
    return [a, b];
  }
  function inRange(x, r){ return x >= r[0] && x <= r[1]; }

  function apply(){
    var r = {
      ms:     readRange('ms'),
      rho:    readRange('rho'),
      ellp:   readRange('ellp'),
      eta:    readRange('eta'),
      theta:  readRange('theta'),
      ncols:  readRange('ncols'),
      chainW: readRange('chainW'),
      chainL: readRange('chainL')
    };
    function keep(v){
      return inRange(v[dims.ms],    r.ms)
          && inRange(v[dims.rho],   r.rho)
          && inRange(v[dims.ellp],  r.ellp)
          && inRange(v[dims.eta],   r.eta)
          && inRange(v[dims.theta], r.theta)
          && inRange(v[dims.ncols], r.ncols)
          && inRange(v[dims.chainW], r.chainW)
          && inRange(v[dims.chainL], r.chainL);
    }
    var flf = allLF.filter(keep).map(function(v){ return {value:v}; });
    var fsf = allSF.filter(keep).map(function(v){ return {value:v}; });
    chart.setOption({ series: [{data: flf}, {data: fsf}] });
    var total = flf.length + fsf.length;
    elem(prefix+'stats').textContent = 'Showing '+total+' points (Large-field: '+flf.length+', Small-field: '+fsf.length+').';
  }

  Object.keys(S).forEach(function(k){
    var ids = S[k].ids;
    elem(ids[0]).addEventListener('input', apply);
    elem(ids[1]).addEventListener('input', apply);
  });

  apply();
})();`
	sc.AddJSFuncs(js)
}

func main() {
	inPath := flag.String("in", "Additionnals/general_sweep.json", "input sweep JSON/JSONL file")
	outPath := flag.String("out", "plot_sweep.html", "output HTML file")
	minBits := flag.Float64("min-bits", 0.0, "optional filter: keep rows with TotalBits ≥ this value")
	flag.Parse()

	resolvedIn, err := resolveSweepPath(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		os.Exit(1)
	}
	if resolvedIn != *inPath {
		fmt.Fprintf(os.Stderr, "[info] using %s (resolved from %s)\n", resolvedIn, *inPath)
	}

	rows, err := readSweepRows(resolvedIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[debug] rows loaded from %s: %d\n", resolvedIn, len(rows))

	reportTopParameterSets(rows, resolvedIn, *minBits)

	lf, sf, minTime, maxTime := buildSeries(rows, *minBits)
	if maxTime < minTime {
		maxTime = minTime
	}
	if maxTime == minTime {
		maxTime = minTime + 1
	}

	// Build the interactive scatter with go-echarts
	page := components.NewPage().SetPageTitle("Proof Size vs. Bit Security")

	sc := charts.NewScatter()
	sc.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "Proof Size vs. Bit Security",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
			Formatter: opts.FuncOpts(`
function (p) {
  var v = p.value || [];
  function fix2(x){
    if (typeof x === 'number') return x.toFixed(2);
    return (x === undefined || x === null) ? '-' : x;
  }
  function fmtExp(x){
    if (typeof x === 'number') {
      return x === 0 ? '0' : x.toExponential(2);
    }
    return '-';
  }
  function check(flag){ return flag ? '✓' : '✗'; }
  function fmtList(arr, fmt){
    return '[' + arr.map(fmt).join(', ') + ']';
  }

  var stage = v[16] || '(stage unknown)';
  var verdict = 'lin ' + check(!!v[17]) + ', eq₄ ' + check(!!v[18]) + ', sum ' + check(!!v[19]);
  var bits = [v[20], v[21], v[22], v[23]];
  var grind = [v[24], v[25], v[26], v[27]];
  var eps = [v[28], v[29], v[30], v[31]];
  var kappa = [v[32], v[33], v[34], v[35]];
  var proofLayers = '';
  if ((v[36] || 0) > 0 || (v[37] || 0) > 0) {
    proofLayers = 'Proof layout: DECS ' + fix2(v[36]) + ' KB, PIOP ' + fix2(v[37]) + ' KB';
  }

  return [
    '<b>' + p.seriesName + '</b> · ' + stage,
    'Bit security: ' + fix2(v[0]) + ' bits',
    'Proof size: ' + fix2(v[1]) + ' KB (' + Math.round((v[1]||0)*1024) + ' bytes)',
    'Time: ' + fix2(v[2]) + ' ms',
    'θ=' + v[3] + ', ρ=' + v[4] + ', ℓ′=' + v[5] + ', ℓ=' + v[6] + ', ncols=' + v[7] + ', η=' + v[8],
    'chain W=' + v[14] + ', chain L=' + v[15],
    'deg=' + v[9] + ', dQ=' + v[10] + ', rows=' + v[12] + ', m=' + v[13],
    proofLayers,
    'Verdict: ' + verdict,
    'ε bits: ' + fmtList(bits, fix2),
    'ε: ' + fmtList(eps, fmtExp),
    'grind bits: ' + fmtList(grind, fix2),
    'κ: ' + fmtList(kappa, function(x){ return (x === undefined || x === null) ? '-' : x; })
  ].filter(Boolean).join('<br/>');
}`),
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(true)}),
		charts.WithXAxisOpts(opts.XAxis{
			Name:      "Bit security (−log₂ total ε)",
			Type:      "value",
			AxisLabel: &opts.AxisLabel{Formatter: "{value}"},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name:      "Proof size (KB)",
			Type:      "value",
			AxisLabel: &opts.AxisLabel{Formatter: "{value}"},
		}),
		// Zoom/pan and toolbox
		charts.WithDataZoomOpts(
			opts.DataZoom{Type: "inside"},
			opts.DataZoom{Type: "slider"},
		),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true)},
				Restore:     &opts.ToolBoxFeatureRestore{Show: opts.Bool(true)},
				DataZoom:    &opts.ToolBoxFeatureDataZoom{Show: opts.Bool(true)},
			},
		}),
		charts.WithVisualMapOpts(opts.VisualMap{
			Type:       "continuous",
			Dimension:  "2",
			Min:        float32(minTime),
			Max:        float32(maxTime),
			Calculable: opts.Bool(true),
			Left:       "left",
			Top:        "middle",
			InRange:    &opts.VisualMapInRange{Color: []string{"#0ea5e9", "#22c55e", "#ef4444"}},
		}),
	)

	// Build scatter series
	lfItems := make([]opts.ScatterData, 0, len(lf))
	for _, p := range lf {
		lfItems = append(lfItems, opts.ScatterData{Value: p.val})
	}
	sfItems := make([]opts.ScatterData, 0, len(sf))
	for _, p := range sf {
		sfItems = append(sfItems, opts.ScatterData{Value: p.val})
	}

	plusSymbol := "path://M-3,-1 L-1,-1 L-1,-3 L1,-3 L1,-1 L3,-1 L3,1 L1,1 L1,3 L-1,3 L-1,1 L-3,1 Z"

	sc.AddSeries("Large-field", lfItems,
		charts.WithScatterChartOpts(opts.ScatterChart{Symbol: "circle", SymbolSize: 7}),
		charts.WithMarkLineNameXAxisItemOpts(opts.MarkLineNameXAxisItem{
			XAxis: 132.0,
			Name:  "132-bit floor",
		}),
		charts.WithMarkLineStyleOpts(opts.MarkLineStyle{
			Label:     &opts.Label{Show: opts.Bool(true)},
			LineStyle: &opts.LineStyle{Type: "dashed", Width: 1},
		}),
	)
	sc.AddSeries("Small-field", sfItems,
		charts.WithScatterChartOpts(opts.ScatterChart{Symbol: plusSymbol, SymbolSize: float32(10)}),
	)

	injectFilterUI(sc)
	page.AddCharts(sc)

	f, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := page.Render(f); err != nil {
		fmt.Fprintf(os.Stderr, "render error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %s | points: LF=%d, SF=%d (min-bits filter: %.2f)\n", *outPath, len(lf), len(sf), *minBits)
}

func resolveSweepPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty input path")
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	var candidates []string
	switch filepath.Ext(path) {
	case ".json":
		candidates = append(candidates, path+"l")
	case "":
		candidates = append(candidates, path+".json", path+".jsonl")
	default:
		// fall back to trying json/jsonl siblings
		base := path[:len(path)-len(filepath.Ext(path))]
		candidates = append(candidates, base+".json", base+".jsonl")
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}

	return "", fmt.Errorf("unable to find sweep input at %s", path)
}

func readSweepRows(path string) ([]SweepRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input %s is empty", path)
	}

	var rows []SweepRow
	if trimmed[0] == '[' {
		rows, err = decodeSweepArray(trimmed)
	} else {
		rows, err = decodeSweepJSONL(data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no valid sweep rows found in %s", path)
	}
	return rows, nil
}

func decodeSweepArray(data []byte) ([]SweepRow, error) {
	var firstErr error
	if rows, err := decodeEnvelopedArray(data); err == nil {
		if len(rows) > 0 {
			return rows, nil
		}
	} else {
		firstErr = err
	}
	if rows, err := decodePlainRowArray(data); err == nil {
		if len(rows) > 0 {
			return rows, nil
		}
	} else if firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("JSON array did not contain any valid sweep reports")
}

func decodeEnvelopedArray(data []byte) ([]SweepRow, error) {
	var env []sweepRecord
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	rows := make([]SweepRow, 0, len(env))
	for _, rec := range env {
		row := rec.Report
		row.Stage = rec.Stage
		if !isRowValid(row) {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func decodePlainRowArray(data []byte) ([]SweepRow, error) {
	var rowsRaw []SweepRow
	if err := json.Unmarshal(data, &rowsRaw); err != nil {
		return nil, err
	}
	rows := make([]SweepRow, 0, len(rowsRaw))
	for _, row := range rowsRaw {
		if !isRowValid(row) {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func decodeSweepJSONL(data []byte) ([]SweepRow, error) {
	reader := bytes.NewReader(data)
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 0, 256<<10), 16<<20)
	var rows []SweepRow
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec sweepRecord
		if err := json.Unmarshal(line, &rec); err == nil {
			row := rec.Report
			row.Stage = rec.Stage
			if !isRowValid(row) {
				continue
			}
			rows = append(rows, row)
			continue
		}
		var plain SweepRow
		if err := json.Unmarshal(line, &plain); err != nil {
			continue
		}
		if !isRowValid(plain) {
			continue
		}
		rows = append(rows, plain)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func isRowValid(r SweepRow) bool {
	return r.ProofBytes > 0 && r.Soundness.TotalBits > 0
}

func bytesToKB(v int) float64 {
	if v == 0 {
		return 0
	}
	return float64(v) / 1024.0
}

func buildSeries(rows []SweepRow, minBits float64) (largeField []point, smallField []point, minTime float64, maxTime float64) {
	toPoint := func(r SweepRow) point {
		proofKB := float64(r.ProofBytes) / 1024.0
		timeUS := int64(0)
		if r.TimingsUS != nil {
			if v, ok := r.TimingsUS["__total__"]; ok {
				timeUS = v
			}
		}
		timeMS := float64(timeUS) / 1000.0

		kappa := padInts(r.Opts.Kappa, 4)
		bits := padFloats(r.Soundness.Bits, 4)
		grindBits := padFloats(r.Soundness.GrindingBits, 4)
		eps := padFloats(r.Soundness.Eps, 4)
		stage := r.Stage
		if stage == "" {
			stage = "(unknown)"
		}
		okLin, okEq4, okSum := 0, 0, 0
		if r.Verdict.OkLin {
			okLin = 1
		}
		if r.Verdict.OkEq4 {
			okEq4 = 1
		}
		if r.Verdict.OkSum {
			okSum = 1
		}
		proofDecs := bytesToKB(r.ProofSizeLayers["DECS"])
		proofPiop := bytesToKB(r.ProofSizeLayers["PIOP"])

		val := []interface{}{
			r.Soundness.TotalBits,
			proofKB,
			timeMS,
			r.Opts.Theta,
			r.Opts.Rho,
			r.Opts.EllPrime,
			r.Opts.Ell,
			r.Opts.NCols,
			r.Opts.Eta,
			r.Degree,
			r.Soundness.DQ,
			r.Opts.DQOverride,
			r.Soundness.NRows,
			r.Soundness.M,
			r.Opts.ChainW,
			r.Opts.ChainL,
			stage,
			okLin,
			okEq4,
			okSum,
			bits[0], bits[1], bits[2], bits[3],
			grindBits[0], grindBits[1], grindBits[2], grindBits[3],
			eps[0], eps[1], eps[2], eps[3],
			kappa[0], kappa[1], kappa[2], kappa[3],
			proofDecs,
			proofPiop,
		}

		return point{
			totalBits: r.Soundness.TotalBits,
			proofKB:   proofKB,
			timeMS:    timeMS,
			val:       val,
		}
	}

	minTime = math.Inf(1)
	maxTime = math.Inf(-1)

	for _, r := range rows {
		if r.Soundness.TotalBits < minBits {
			continue
		}
		p := toPoint(r)
		if p.timeMS < minTime {
			minTime = p.timeMS
		}
		if p.timeMS > maxTime {
			maxTime = p.timeMS
		}
		if r.Opts.Theta > 1 {
			smallField = append(smallField, p)
		} else {
			largeField = append(largeField, p)
		}
	}

	if len(largeField) == 0 && len(smallField) == 0 {
		minTime, maxTime = 0, 0
	} else {
		if minTime == math.Inf(1) {
			minTime = 0
		}
		if maxTime == math.Inf(-1) {
			maxTime = 0
		}
	}

	sort.Slice(largeField, func(i, j int) bool { return largeField[i].proofKB < largeField[j].proofKB })
	sort.Slice(smallField, func(i, j int) bool { return smallField[i].proofKB < smallField[j].proofKB })
	return
}

func padInts(v []int, n int) []int {
	out := make([]int, n)
	for i := 0; i < n && i < len(v); i++ {
		out[i] = v[i]
	}
	return out
}
func padFloats(v []float64, n int) []float64 {
	out := make([]float64, n)
	for i := 0; i < n && i < len(v); i++ {
		out[i] = v[i]
	}
	return out
}
