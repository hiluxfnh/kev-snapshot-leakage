#!/usr/bin/env bash
# Reproduce everything. Run from the repository root, after cloning the raw data (see docs/SOURCES.md).
set -e
cd code
python3 parse_cve.py ../raw/cvelistV5 ../data/cve_all.pkl
python3 prep.py
python3 exp_desc.py
for H in 90 30 365; do python3 exp_main.py $H | tee ../logs/log_main$H.txt; done
python3 exp_base.py
python3 exp_abl.py
python3 figs.py
python3 gen_tables.py
cd ../paper && pdflatex paper.tex && pdflatex paper.tex
