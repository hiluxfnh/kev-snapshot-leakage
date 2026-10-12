"""Disclosure-time reconstruction. Compare the snapshot record with the record as first committed to the CVE List repository.
Scenarios (train features -> test features): snap->snap (what the literature usually does), hist->hist (what a deployed model could see), snap->hist (model trained on today's records, applied to disclosure-time records)."""
import numpy as np, pandas as pd, json, sys, warnings
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
import lightgbm as lgb
from kev_lib import *
from exp_gbm_lib import FeatSmall, PARAMS
H = 90; END = '2026-07-10'; START = '2023-04-01'
snap = pd.read_pickle('../data/table.pkl'); hist = pd.read_pickle('../data/table_hist2.pkl')
snap = snap[snap.cve.isin(hist.cve) & (snap.pub >= START) & (snap.pub <= END)].sort_values('cve').reset_index(drop=True)
hist = hist.set_index('cve').loc[snap.cve].reset_index()
hist['pub'] = snap.pub.values; hist['days_to_kev'] = snap.days_to_kev.values
y = ((snap.days_to_kev <= H) & snap.days_to_kev.notna()).astype(int).values
print('cohort', len(snap), 'pos', y.sum(), flush=True)
# ---- descriptive: indicators at publication vs final snapshot
def ind(d):
    t = d.desc.fillna('').str.lower()
    return {'CISA kev block': d.adp_kev_date.notna(), 'SSVC exploitation present': d.ssvc_exploitation.notna(), 'any ADP container': d.n_adp > 0,
            'CVSS exploit maturity F/H': d.t_E.isin(['F', 'H']), 'in the wild in description': t.str.contains('in the wild'),
            'updated >30d after publication': d.upd_lag_days > 30, 'vendor advisory tag': d.ref_tags.fillna('').str.contains('vendor-advisory'),
            'GitHub reference': d.ref_domains.fillna('').str.contains('github.com')}
desc = {}
for name, d in (('snapshot', snap), ('published', hist)):
    for k, v in ind(d).items():
        v = v.values; desc.setdefault(k, {})[name] = {'pos': float(v[y == 1].mean()), 'neg': float(v[y == 0].mean())}
# how much do "safe" fields change after publication
chg = {'description changed': float((snap.desc.fillna('') != hist.desc.fillna('')).mean()), 'title changed': float((snap.title.fillna('') != hist.title.fillna('')).mean()),
       'CWE changed': float((snap.cwes.fillna('') != hist.cwes.fillna('')).mean()), 'CNA CVSS v3 vector changed': float((snap.cna_v31_vec.fillna('') != hist.cna_v31_vec.fillna('')).mean()),
       'vendors changed': float((snap.vendors.fillna('') != hist.vendors.fillna('')).mean()), 'products changed': float((snap.products.fillna('') != hist.products.fillna('')).mean()),
       'reference count changed': float((snap.n_refs != hist.n_refs).mean())}
chg_pos = {k: float(v) for k, v in {'description changed': (snap.desc.fillna('') != hist.desc.fillna('')).values[y == 1].mean(), 'reference count changed': (snap.n_refs != hist.n_refs).values[y == 1].mean(), 'CNA CVSS v3 vector changed': (snap.cna_v31_vec.fillna('') != hist.cna_v31_vec.fillna('')).values[y == 1].mean()}.items()}
json.dump({'n': len(snap), 'pos': int(y.sum()), 'indicators': desc, 'changed_all': chg, 'changed_pos': chg_pos}, open('../results/results_hist_desc.json', 'w'), indent=1)
print(json.dumps(desc, indent=0)[:1500]); print(chg, chg_pos, flush=True)
# ---- models
CFGS = {'S': [], 'S+temporal': ['C_temporal'], 'S+refs': ['C_refs'], 'S+update': ['C_update'], 'S+enrich': ['C_enrich'], 'S+kevfield': ['C_kevfield'], 'S+all_C': ['C_temporal', 'C_refs', 'C_update', 'C_enrich', 'C_kevfield']}
import os
OUTF = '../results/results_hist.jsonl'; done = set()
if os.path.exists(OUTF):
    for l in open(OUTF): r = json.loads(l); done.add((r['model'], r['test'], r['cfg'], r['scenario']))
rng = np.random.default_rng(0); out = open(OUTF, 'a')
for Y in (2024, 2025, 2026):
    t0 = pd.Timestamp(f'{Y}-01-01'); t1 = pd.Timestamp(f'{Y+1}-01-01')
    te = np.where((snap.pub >= t0) & (snap.pub < t1))[0]; tr = np.where(snap.pub <= t0 - pd.Timedelta(days=H))[0]
    if len(te) == 0 or y[te].sum() == 0: continue
    for name, g in CFGS.items():
        for model in ('lr', 'lgbm'):
            if model == 'lgbm' and name not in ('S', 'S+enrich', 'S+all_C'): continue
            FF = Feat if model == 'lr' else FeatSmall
            for scen, (A, B) in {'snap->snap': (snap, snap), 'hist->hist': (hist, hist), 'snap->hist': (snap, hist)}.items():
                if (model, Y, name, scen) in done: continue
                f = FF(g).fit(A.loc[tr]); Xtr = f.transform(A.loc[tr]); Xte = f.transform(B.loc[te])
                if model == 'lr': s = LogisticRegression(solver='liblinear', C=1.0, max_iter=200).fit(Xtr, y[tr]).decision_function(Xte)
                else: s = lgb.LGBMClassifier(random_state=0, **PARAMS).fit(Xtr.astype(np.float32), y[tr]).predict_proba(Xte.astype(np.float32))[:, 1]
                r = dict(model=model, test=Y, cfg=name, scenario=scen, n_train=len(tr), pos_train=int(y[tr].sum()), **metrics(y[te], s, rng, 100))
                out.write(json.dumps(r) + '\n'); out.flush(); print(model, Y, name, scen, round(r['auc'], 3), round(r['ap'], 3), flush=True)
