"""Build the analysis table: published CVEs + KEV labels (from the CISA catalog) + parsed dates and CVSS components."""
import pandas as pd, json, numpy as np, re
p = pd.read_pickle('../data/cve_all.pkl'); p = p[p.state == 'PUBLISHED'].copy()
k = pd.DataFrame(json.load(open('../raw/kev-data/known_exploited_vulnerabilities.json'))['vulnerabilities'])
def d(s): return pd.to_datetime(s, utc=True, format='ISO8601', errors='coerce').dt.tz_localize(None)
p['pub'] = d(p.published).dt.normalize(); p['upd'] = d(p.updated); p['res'] = d(p.reserved)
k['added'] = pd.to_datetime(k.dateAdded)
p = p.merge(k[['cveID', 'added', 'vendorProject', 'product', 'knownRansomwareCampaignUse']], left_on='cve', right_on='cveID', how='left').drop(columns='cveID')
p['days_to_kev'] = (p.added - p.pub).dt.days
# CVSS parsing: take the CNA's v3.1 else v3.0 vector; split base and temporal parts
def split(v):
    if not isinstance(v, str): return {}
    out = {}
    for part in v.split('/')[1:]:
        if ':' in part: a, b = part.split(':', 1); out[a] = b
    return out
vec = p.cna_v31_vec.fillna(p.cna_v30_vec)
comp = pd.DataFrame([split(v) for v in vec], index=p.index)
for c in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']: p['b_' + c] = comp[c] if c in comp else None
for c in ['E', 'RL', 'RC']: p['t_' + c] = comp[c] if c in comp else None
v4 = pd.DataFrame([split(v) for v in p.cna_v40_vec], index=p.index)
for c in ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']: p['v4_' + c] = v4[c] if c in v4 else None
p['v4_E'] = v4['E'] if 'E' in v4 else None
p['base_score'] = p.cna_v31_score.fillna(p.cna_v30_score)
p['cvss_version'] = np.where(p.cna_v40_vec.notna(), 'v4', 'none')
p['upd_lag_days'] = (p.upd - p.pub).dt.days
p['n_cwe'] = p.cwes.fillna('').str.split().str.len()
p.to_pickle('../data/table.pkl'); print(p.shape)
print(p[['t_E','t_RL','t_RC','v4_E']].notna().sum().to_dict())
