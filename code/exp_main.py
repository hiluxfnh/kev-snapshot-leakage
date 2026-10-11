import numpy as np, pandas as pd, json, time, sys, os, warnings
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from kev_lib import *
H = int(sys.argv[1]) if len(sys.argv) > 1 else 90
END = {30: '2026-09-08', 90: '2026-07-10', 365: '2025-10-08'}[H]
p = pd.read_pickle('../data/table.pkl')
c = p[(p.pub >= '2021-11-03') & (p.pub <= END)].copy().reset_index(drop=True)
c['y'] = ((c.days_to_kev <= H) & c.days_to_kev.notna()).astype(int)
print('cohort', len(c), 'pos', c.y.sum(), flush=True)
OUT = f'../results/results_main_H{H}.jsonl'; done = set()
if os.path.exists(OUT): done = {(json.loads(l)['protocol'], json.loads(l)['fold'], json.loads(l)['cfg']) for l in open(OUT)}
CFGS = {'S': [], 'S+temporal': ['C_temporal'], 'S+refs': ['C_refs'], 'S+update': ['C_update'], 'S+enrich': ['C_enrich'], 'S+kevfield': ['C_kevfield'],
        'S+all_C': ['C_temporal', 'C_refs', 'C_update', 'C_enrich', 'C_kevfield']}
rng = np.random.default_rng(0)
def run(protocol, fold, tr, te):
    for name, g in CFGS.items():
        if (protocol, fold, name) in done: continue
        t0 = time.time(); f = Feat(g).fit(c.loc[tr]); Xtr = f.transform(c.loc[tr]); Xte = f.transform(c.loc[te])
        m = LogisticRegression(solver='liblinear', C=1.0, max_iter=200).fit(Xtr, c.y[tr]); s = m.decision_function(Xte)
        r = dict(protocol=protocol, fold=fold, cfg=name, H=H, n_train=len(tr), pos_train=int(c.y[tr].sum()), nfeat=Xtr.shape[1], **metrics(c.y[te], s, rng, 200))
        with open(OUT, 'a') as fh: fh.write(json.dumps(r) + '\n')
        print(protocol, fold, name, round(r['auc'], 4), round(r['ap'], 4), f'{time.time()-t0:.0f}s', flush=True)
# 1. random stratified 5-fold
skf = StratifiedKFold(5, shuffle=True, random_state=0)
for i, (tr, te) in enumerate(skf.split(c, c.y)): run('random', f'fold{i}', tr, te)
# 2. temporal: test year Y, naive vs delay-aware training sets
for Y in (2024, 2025, 2026):
    t0 = pd.Timestamp(f'{Y}-01-01'); t1 = pd.Timestamp(f'{Y+1}-01-01')
    te = c.index[(c.pub >= t0) & (c.pub < t1)]
    naive = c.index[c.pub < t0]; aware = c.index[c.pub <= t0 - pd.Timedelta(days=H)]
    run('temporal_aware', f'test{Y}', aware, te); run('temporal_naive', f'test{Y}', naive, te)
print('DONE')
