"""Rebuild each cohort CVE record as it looked in the first commit that added it to the CVE List repository
(= the day of publication), using the same parser as the final snapshot. Output: ../data/table_hist.pkl"""
import json, subprocess, sys, pandas as pd
from parse_cve import parse_record
REPO = '../raw/cvelistV5'
m = pd.read_pickle('../data/hist_cohort.pkl')
oids = m.oid.tolist()
p = subprocess.Popen(['git', '-C', REPO, 'cat-file', '--batch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
rows = []
for cve, o in zip(m.cve, oids):
    p.stdin.write((o + '\n').encode()); p.stdin.flush()
    hdr = p.stdout.readline().split()
    if hdr[1] != b'blob': continue
    n = int(hdr[2]); data = p.stdout.read(n); p.stdout.read(1)
    try: r = parse_record(json.loads(data))
    except Exception: continue
    if r: rows.append(r)
h = pd.DataFrame(rows); h.to_pickle('../data/table_hist.pkl'); print(h.shape, h.state.value_counts().to_dict())
