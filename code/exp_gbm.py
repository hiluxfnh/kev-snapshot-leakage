"""Second model family: gradient boosted trees (LightGBM) on the same feature groups.
Usage: python3 exp_gbm.py H   (H=90 default). Writes ../results/results_gbm_H{H}.jsonl"""
import numpy as np, pandas as pd, json, time, sys, os, warnings
warnings.filterwarnings('ignore')
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
import kev_lib
from kev_lib import *
H = int(sys.argv[1]) if len(sys.argv) > 1 else 90
END = {30: '2026-09-08', 90: '2026-07-10', 365: '2025-10-08'}[H]
SEEDS = [0, 1, 2]
p = pd.read_pickle('../data/table.pkl')
c = p[(p.pub >= '2021-11-03') & (p.pub <= END)].copy().reset_index(drop=True)
c['y'] = ((c.days_to_kev <= H) & c.days_to_kev.notna()).astype(int)
OUT = f'../results/results_gbm_H{H}.jsonl'; done = set()
if os.path.exists(OUT):
    for l in open(OUT): r = json.loads(l); done.add((r['protocol'], r['fold'], r['cfg'], r['seed']))
CFGS = {'S': [], 'S+temporal': ['C_temporal'], 'S+refs': ['C_refs'], 'S+update': ['C_update'], 'S+enrich': ['C_enrich'], 'S+kevfield': ['C_kevfield'],
        'S+all_C': ['C_temporal', 'C_refs', 'C_update', 'C_enrich', 'C_kevfield']}
from exp_gbm_lib import FeatSmall, PARAMS
rng = np.random.default_rng(0)
def run(protocol, fold, tr, te, seeds, only=None):
    for name, g in CFGS.items():
        if only and name not in only: continue
        sd = seeds if name not in ('S+kevfield', 'S+all_C') else seeds[:1]  # near-perfect configs: one seed is enough
        todo = [s for s in sd if (protocol, fold, name, s) not in done]
        if not todo: continue
        t0 = time.time(); f = FeatSmall(g).fit(c.loc[tr]); Xtr = f.transform(c.loc[tr]).astype(np.float32); Xte = f.transform(c.loc[te]).astype(np.float32)
        for s in todo:
            m = lgb.LGBMClassifier(random_state=s, **PARAMS).fit(Xtr, c.y[tr]); sc = m.predict_proba(Xte)[:, 1]
            r = dict(model='lgbm', protocol=protocol, fold=fold, cfg=name, seed=s, H=H, n_train=len(tr), pos_train=int(c.y[tr].sum()), nfeat=Xtr.shape[1], **metrics(c.y[te], sc, rng, 100 if protocol != 'random' else 0))
            with open(OUT, 'a') as fh: fh.write(json.dumps(r) + '\n')
            print(protocol, fold, name, s, round(r['auc'], 4), round(r['ap'], 4), f'{time.time()-t0:.0f}s', flush=True)
for Y in (2024, 2025, 2026):
    t0 = pd.Timestamp(f'{Y}-01-01'); t1 = pd.Timestamp(f'{Y+1}-01-01')
    te = c.index[(c.pub >= t0) & (c.pub < t1)]
    if len(te) == 0: continue
    aware = c.index[c.pub <= t0 - pd.Timedelta(days=H)]
    run('temporal_aware', f'test{Y}', aware, te, SEEDS)
skf = StratifiedKFold(5, shuffle=True, random_state=0)
for i, (tr, te) in enumerate(skf.split(c, c.y)): run('random', f'fold{i}', tr, te, [0], only=('S', 'S+all_C'))
print('DONE')
