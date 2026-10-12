# Additions for the repository (second model and as-published reconstruction)

Copy these folders over the repository root (same names: code/, results/, logs/, paper/, data/). Then add the lines below to README.md and docs/SOURCES.md.

New code
- code/parse_hist.py : reads every cohort CVE as first committed to the CVE List repo (git cat-file) and parses it with the same parser as the snapshot.
- code/prep_hist.py : builds the as-published table (same steps as prep.py).
- code/exp_hist.py : snap->snap, hist->hist, snap->hist experiments (logistic regression and LightGBM).
- code/exp_gbm.py, code/exp_gbm_lib.py : LightGBM runs on the full cohort.
- code/gen_tables2.py : tables for the new paper sections.
- code/parse_cve.py and code/kev_lib.py changed slightly (parse_record function; empty-vocabulary fallback). Results of the earlier experiments do not change.

New data and results
- data/cohort_as_published_2023-04_to_2026-07_derived.csv.xz : 148,069 records as first published (469 positives at 90 days).
- results/results_gbm_H90.jsonl, results/results_hist.jsonl, results/results_hist_desc.json.

How to reproduce the history part (needs a full-history clone, about 1 GB for the blobless clone plus the fetched blobs)
  git clone --filter=blob:none --no-checkout https://github.com/CVEProject/cvelistV5.git raw/cvelistV5
  git -C raw/cvelistV5 log --no-renames --diff-filter=A --raw --no-abbrev --since=2023-03-29 --format='C %H %aI' -- cves > data/added_raw.txt
    cd code && python3 build_first_add.py ; then fetch the blobs: git -C raw/cvelistV5 fetch origin --no-tags --filter=blob:none $(cat data/oids.txt | tr "\n" " ") (in chunks of 4000)
  python3 parse_hist.py && python3 prep_hist.py && python3 exp_hist.py && python3 exp_gbm.py 90 && python3 gen_tables2.py
Run python3 build_first_add.py before parse_hist.py (it writes first_add2.pkl, hist_cohort.pkl and oids.txt).

Package versions: LightGBM 4.x, scikit-learn 1.9.1 (add lightgbm to requirements.txt).
