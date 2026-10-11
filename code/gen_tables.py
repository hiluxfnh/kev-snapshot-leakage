import json, os, numpy as np, pandas as pd
P='../paper/'
def W(name,rows):
    t='\n'.join(x for x in rows if x).rstrip()
    assert t.endswith('\\\\'); open(P+name,'w').write(t[:-2].rstrip()+'\n')
def load(H):
    f=f'../results/results_main_H{H}.jsonl'
    return pd.DataFrame([json.loads(l) for l in open(f)]) if os.path.exists(f) else None
names={'S':'Safe set S','S+temporal':'S + CVSS temporal','S+refs':'S + references','S+update':'S + update lag','S+enrich':'S + ADP enrichment','S+kevfield':'S + KEV field','S+all_C':'S + all contaminated'}
r=load(90)
def f3(x): return f'{x:.3f}'
rows=[]
for k,n in names.items():
    a=r[(r.protocol=='random')&(r.cfg==k)]; t=r[(r.protocol=='temporal_aware')&(r.cfg==k)]; v=r[(r.protocol=='temporal_naive')&(r.cfg==k)]
    rows.append(f"{n} & {f3(a.auc.mean())} & {f3(a.ap.mean())} & {f3(t.auc.mean())} & {f3(t.ap.mean())} & {f3(v.auc.mean())} & {f3(v.ap.mean())} \\\\")
W('tab_main.tex',rows)
# per-year S model with CI, and baselines
b=json.load(open('../results/results_baselines_H90.json')); bd=pd.DataFrame(b)
rows=[]
for Y in (2024,2025,2026):
    s=r[(r.protocol=='temporal_aware')&(r.cfg=='S')&(r.fold==f'test{Y}')].iloc[0]
    rows.append(f"{Y} & Logistic model, set S & {int(s.n):,} & {int(s.pos)} & {f3(s.auc)} ({s.auc_ci[0]:.2f}-{s.auc_ci[1]:.2f}) & {f3(s.ap)} ({s.ap_ci[0]:.3f}-{s.ap_ci[1]:.3f}) & {s.prec_top1:.3f} & {s.rec_top5:.2f} \\\\")
    for key,lab in (('cvss_score','CVSS base score'),('network_easy_vector','Easy network vector'),('vendor_prior','Vendor prior')):
        x=bd[(bd.test==Y)&(bd.rule==key)].iloc[0]
        rows.append(f" & {lab} & & & {f3(x['auc'])} ({x['auc_ci'][0]:.2f}-{x['auc_ci'][1]:.2f}) & {f3(x['ap'])} ({x['ap_ci'][0]:.3f}-{x['ap_ci'][1]:.3f}) & {x['prec_top1']:.3f} & {x['rec_top5']:.2f} \\\\")
    if Y<2026: rows.append('\\midrule')
W('tab_year.tex',rows)
# horizons
rows=[]
for H in (30,90,365):
    d=load(H)
    if d is None: continue
    g=lambda proto,cfg,m: d[(d.protocol==proto)&(d.cfg==cfg)][m].mean()
    ln=open(f'../logs/log_main{H}.txt').readline().split(); coh=int(ln[1]); npos=int(ln[3])
    rows.append(f"{H} & {coh:,} & {npos} & {f3(g('random','S','ap'))} & {f3(g('temporal_aware','S','ap'))} & {f3(g('temporal_naive','S','ap'))} & {f3(g('temporal_aware','S+temporal','ap'))} & {f3(g('temporal_aware','S+kevfield','ap'))} \\\\")
W('tab_h.tex',rows)
a=pd.DataFrame(json.load(open('../results/results_ablation_H90.json')))
lab={'S':'Full text (set S)','S_scrubbed':'Exploit wording removed','S_no_text':'No text features'}
rows=[]
for k,l in lab.items():
    x=a[a.cfg==k].sort_values('test'); rows.append(l+' & '+' & '.join(f"{f3(u)} & {f3(v)}" for u,v in zip(x.auc,x.ap))+' \\\\')
W('tab_abl.tex',rows)
print('tables ok')
