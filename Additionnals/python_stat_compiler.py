#!/usr/bin/env python3
import argparse, json, sys, glob, os
from collections import defaultdict


def fmt_bytes(n):
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if n < 1024 or unit == "GiB":
            if unit == "B":
                return f"{n:.0f} {unit}"
            return f"{n/1024:.1f} {unit}"
        n /= 1024

def load_rows(input_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(input_dir, "*.json"))):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                print(f"[warn] {path} ignored: top-level JSON is not a list/dict", file=sys.stderr)
                continue
            rows.extend(data)
        except Exception as e:
            print(f"[warn] failed to parse {path}: {e}", file=sys.stderr)
    return rows

def get_opt(opts, row, key):
    if isinstance(opts, dict) and key in opts:
        return opts[key]
    return row.get(key, 0)

def derive(row):
    opts = row.get("Opts", {})
    ncols = get_opt(opts, row, "NCols")
    ell = get_opt(opts, row, "Ell")
    ellp = get_opt(opts, row, "EllPrime")
    rho = get_opt(opts, row, "Rho")
    eta = get_opt(opts, row, "Eta")
    theta = get_opt(opts, row, "Theta")

    verdict = row.get("Verdict", {}) or {}
    ok_lin = bool(verdict.get("OkLin", False))
    ok_eq4 = bool(verdict.get("OkEq4", False))
    ok_sum = bool(verdict.get("OkSum", False))
    ok_all = ok_lin and ok_eq4 and ok_sum

    times = row.get("TimingsUS", {}) or {}
    total_us = times.get("__total__")
    if total_us is None:
        total_us = sum(times.values())
    t_norm = float(times.get("buildFparLinfChain", 0.0))

    sizes = row.get("SizesB", {}) or {}
    size_total = sum(int(v) for v in sizes.values())
    size_fpar_total = sum(int(v) for k, v in sizes.items() if k.startswith("piop/Fpar/"))
    size_fpar_core = int(sizes.get("piop/Fpar/core", 0))
    size_fpar_norm = int(sizes.get("piop/Fpar/linf_chain", 0))
    size_witness_total = sum(int(v) for k, v in sizes.items() if k.startswith("piop/witness/"))
    size_witness_norm = int(sizes.get("piop/witness/linf_chain/M", 0)) + int(sizes.get("piop/witness/linf_chain/D", 0))

    return {
        "Ncols": int(ncols),
        "ell": int(ell),
        "ellp": int(ellp),
        "rho": int(rho),
        "eta": int(eta),
        "theta": int(theta),
        "ok_lin": ok_lin,
        "ok_eq4": ok_eq4,
        "ok_sum": ok_sum,
        "ok_all": ok_all,
        "t_total_ms": float(total_us) / 1000.0,
        "t_norm_ms": t_norm / 1000.0,
        "size_fpar_core": int(size_fpar_core),
        "size_fpar_norm": int(size_fpar_norm),
        "size_fpar_total": int(size_fpar_total),
        "size_witness_norm": int(size_witness_norm),
        "size_witness_total": int(size_witness_total),
        "size_total_bytes": int(size_total),
    }

def write_markdown(rows, out_path):
    hdr = [
        "Ncols", "ell", "ellp", "rho", "eta", "theta",
        "OK", "t_total(ms)", "t_norm(ms)",
        "Fpar(core)", "Fpar(norm)", "Fpar(total)",
        "Wit(norm)", "Wit(total)", "All(sizes)",
    ]
    lines = []
    lines.append("| " + " | ".join(hdr) + " |")
    lines.append("|" + "|".join(["---"] * len(hdr)) + "|")
    rows_sorted = sorted(rows, key=lambda r: (r["Ncols"], r["ell"], r["ellp"], r["rho"], r["eta"], r["theta"]))
    for r in rows_sorted:
        rec = [
            str(r["Ncols"]), str(r["ell"]), str(r["ellp"]), str(r["rho"]), str(r["eta"]), str(r["theta"]),
            "✔" if r["ok_all"] else "✘",
            f"{r['t_total_ms']:.0f}", f"{r['t_norm_ms']:.0f}",
            fmt_bytes(r["size_fpar_core"]),
            fmt_bytes(r["size_fpar_norm"]),
            fmt_bytes(r["size_fpar_total"]),
            fmt_bytes(r["size_witness_norm"]),
            fmt_bytes(r["size_witness_total"]),
            fmt_bytes(r["size_total_bytes"]),
        ]
        lines.append("| " + " | ".join(rec) + " |")
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"[ok] wrote {out_path}")

def write_csv(rows, out_path):
    import csv
    hdr = [
        "Ncols", "ell", "ellp", "rho", "eta", "theta",
        "ok_lin", "ok_eq4", "ok_sum", "ok_all",
        "t_total_ms", "t_norm_ms",
        "size_fpar_core", "size_fpar_norm", "size_fpar_total",
        "size_witness_norm", "size_witness_total", "size_total_bytes",
    ]
    rows_sorted = sorted(rows, key=lambda r: (r["Ncols"], r["ell"], r["ellp"], r["rho"], r["eta"], r["theta"]))
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(hdr)
        for r in rows_sorted:
            w.writerow([r[k] for k in hdr])
    print(f"[ok] wrote {out_path}")

def main():
    ap = argparse.ArgumentParser(description="Summarize PACS benchmark JSONs into Markdown/CSV tables.")
    ap.add_argument("--in", dest="inp", default="out", help="directory with *.json results (default: ./out)")
    ap.add_argument("--md", dest="md", default="summary.md", help="output Markdown file")
    ap.add_argument("--csv", dest="csv", default="summary.csv", help="output CSV file")
    args = ap.parse_args()

    rows_raw = load_rows(args.inp)
    if not rows_raw:
        print(f"[err] no JSON files found in {args.inp}", file=sys.stderr)
        sys.exit(1)

    derived = [derive(r) for r in rows_raw]
    write_markdown(derived, args.md)
    write_csv(derived, args.csv)

if __name__ == "__main__":
    main()
