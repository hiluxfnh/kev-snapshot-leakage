"""Tables for the second model family and the disclosure-time reconstruction (written to ../paper/)."""
import pandas as pd, json, numpy as np
P = '../paper/'
def w(name, lines): open(P + name, 'w').write('\n'.join(lines))
pct = lambda x: f'{100*x:.1f}\\%' if x >= 0.001 else ('0\\%' if x == 0 else f'{100*x:.2f}\\%')
# ---- Table: indicators at publication vs snapshot
d = json.load(open('../results/results_hist_desc.json'))
rows = []
for k in ['CISA kev block', 'SSVC exploitation present', 'any ADP container', 'CVSS exploit maturity F/H', 'in the wild in description', 'updated >30d after publication', 'vendor advisory tag', 'GitHub reference']:
    v = d['indicators'][k]; kk = k.replace('>', '$>$').replace('&', '\\&')
    rows.append(f"{kk} & {pct(v['snapshot']['pos'])} & {pct(v['published']['pos'])} & {pct(v['snapshot']['neg'])} & {pct(v['published']['neg'])}")
w('tab_hist_ind.tex', [r + ' \\\\' if i < len(rows) - 1 else r for i, r in enumerate(rows)])
ch = d['changed_all']; cp = d['changed_pos']
json.dump({'all': ch, 'pos': cp, 'n': d['n'], 'pos_n': d['pos']}, open('../results/_chg.json', 'w'))
# ---- Table: scenarios
r = pd.DataFrame([json.loads(l) for l in open('../results/results_hist.jsonl')])
r = r[r.test.isin([2025, 2026])]
names = {'S': 'Safe set $S$', 'S+temporal': 'S + CVSS temporal', 'S+refs': 'S + references', 'S+update': 'S + update lag', 'S+enrich': 'S + ADP enrichment', 'S+kevfield': 'S + KEV field', 'S+all_C': 'S + all contaminated'}
rows = []
for cfg, nm in names.items():
    cells = []
    for model in ('lr', 'lgbm'):
        for sc in ('snap->snap', 'hist->hist', 'snap->hist'):
            x = r[(r.model == model) & (r.cfg == cfg) & (r.scenario == sc)]
            cells.append(f'{x.ap.mean():.3f}' if len(x) == 2 else '--')
    rows.append(nm + ' & ' + ' & '.join(cells))
w('tab_hist.tex', [x + ' \\\\' if i < len(rows) - 1 else x for i, x in enumerate(rows)])
# ---- Table: gradient boosting vs logistic regression on the full cohort
g = pd.DataFrame([json.loads(l) for l in open('../results/results_gbm_H90.jsonl')])
lr = {'S': (0.946, 0.227, 0.889, 0.075), 'S+temporal': (0.948, 0.341, 0.895, 0.169), 'S+refs': (0.955, 0.269, 0.901, 0.084), 'S+update': (0.958, 0.295, 0.906, 0.100),
      'S+enrich': (1.0, 0.873, 1.0, 0.822), 'S+kevfield': (1.0, 0.867, 1.0, 0.848), 'S+all_C': (1.0, 0.889, 1.0, 0.869)}  # means copied from tab_main.tex (logistic model, results_main_H90.jsonl)
rows = []
for cfg, nm in names.items():
    t = g[(g.protocol == 'temporal_aware') & (g.cfg == cfg)]; rd = g[(g.protocol == 'random') & (g.cfg == cfg)]
    ta = t.groupby('fold').ap.mean().mean(); tu = t.groupby('fold').auc.mean().mean()
    ra = f'{rd.ap.mean():.3f}' if len(rd) else '--'; ru = f'{rd.auc.mean():.3f}' if len(rd) else '--'
    rows.append(f'{nm} & {lr[cfg][0]:.3f} & {lr[cfg][1]:.3f} & {lr[cfg][2]:.3f} & {lr[cfg][3]:.3f} & {ru} & {ra} & {tu:.3f} & {ta:.3f}')
w('tab_gbm.tex', [x + ' \\\\' if i < len(rows) - 1 else x for i, x in enumerate(rows)])
# seed spread for S
s = g[(g.protocol == 'temporal_aware') & (g.cfg == 'S')].groupby('seed').ap.mean()
json.dump({'S_ap_by_seed': s.round(4).to_dict()}, open('../results/_gbm_seeds.json', 'w')); print(s)
yr = g[(g.protocol == 'temporal_aware') & (g.cfg == 'S')].groupby('fold').ap.agg(['mean', 'min', 'max']); print(yr)
