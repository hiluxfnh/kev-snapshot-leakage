# Snapshot leakage in predicting exploited vulnerabilities from public CVE data

Code, results and paper for "What the Record Remembers: Snapshot Leakage in Predicting Exploited Vulnerabilities from Public CVE Data".

The study asks which fields of a public CVE record carry information that did not exist at disclosure, and how much they inflate models that predict membership in the CISA Known Exploited Vulnerabilities (KEV) catalog. It compares random cross-validation with forward-in-time testing on 183,409 CVEs (90-day label).

## Layout
- `paper/`: LaTeX source, named and anonymous PDFs, generated tables, `figs/`
- `code/`: pipeline (parse, prepare, experiments, baselines, ablation, figures, tables)
- `results/`: raw result files behind every number in the paper
- `logs/`: run logs
- `data/`: derived table of the post-2021-11-03 CVEs (compressed CSV); see `docs/DATA_DICTIONARY.md`
- `docs/`: data sources with exact commits, data dictionary, reference verification notes, venue notes
- `raw/`: empty; clone the public source repositories here (see `docs/SOURCES.md`)

## Reproduce
1. Clone the three source repositories into `raw/` at the commits in `docs/SOURCES.md`.
2. `pip install -r requirements.txt`
3. `./run_all.sh` (a few hours on a laptop; the main run takes about an hour per horizon on one core).

## Notes
- All data are public. Positives are rare (587 of 183,409 at the 90-day horizon), so single-year results carry wide uncertainty; see the paper.

## License
Code under MIT (see `LICENSE`). Source data keep the terms of their original publishers (see `docs/SOURCES.md`).

## Second model and as-published records (added October 2026)

The paper also reports a gradient boosting model (LightGBM) and a reconstruction of every cohort record as it was first committed to the CVE List repository (CVEs published from April 2023). The new scripts are `code/build_first_add.py`, `parse_hist.py`, `prep_hist.py`, `exp_hist.py`, `exp_gbm.py` and `gen_tables2.py`. Results are in `results/results_gbm_H90.jsonl`, `results/results_hist.jsonl` and `results/results_hist_desc.json`; the derived as-published table is `data/cohort_as_published_2023-04_to_2026-07_derived.csv.xz`. Steps to reproduce are in `docs/README_ADDENDUM.md`. The EuroS&P-format paper source is `paper/paper_eurosp.tex`.
