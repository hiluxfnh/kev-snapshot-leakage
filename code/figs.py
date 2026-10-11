import json, os, numpy as np, pandas as pd, matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,'font.family':'DejaVu Sans'})
BL,OR,GR,RD='#0072B2','#D55E00','#7f7f7f','#CC79A7'
def load(H): 
    f=f'../results/results_main_H{H}.jsonl'
    return pd.DataFrame([json.loads(l) for l in open(f)]) if os.path.exists(f) else None
r=load(90); out='../paper/figs/'
order=['S','S+temporal','S+refs','S+update','S+enrich','S+kevfield']
lab=['S\n(safe)','+CVSS\ntemporal','+refs','+update\nlag','+ADP\nenrich','+KEV\nfield']
# Fig 1: AP by feature set and protocol
fig,ax=plt.subplots(figsize=(6.4,3.0))
rnd=r[r.protocol=='random'].groupby('cfg').ap.mean().reindex(order)
ta=r[r.protocol=='temporal_aware'].groupby('cfg').ap.mean().reindex(order)
x=np.arange(len(order)); w=0.38
b1=ax.bar(x-w/2,rnd,w-0.04,color=GR,label='Random 5-fold CV'); b2=ax.bar(x+w/2,ta,w-0.04,color=BL,label='Temporal, delay-aware (mean of 2024-2026)')
for b in list(b1)+list(b2): ax.text(b.get_x()+b.get_width()/2,b.get_height()+0.012,f'{b.get_height():.2f}',ha='center',fontsize=7.5)
ax.set_xticks(x); ax.set_xticklabels(lab); ax.set_ylabel('Average precision'); ax.set_ylim(0,1.0); ax.legend(frameon=False,loc='upper left',fontsize=8)
fig.tight_layout(); fig.savefig(out+'fig_ap.pdf'); fig.savefig(out+'fig_ap.png',dpi=200); plt.close()
# Fig 2: time to KEV CDF
p=pd.read_pickle('../data/table.pkl'); c=p[(p.pub>='2021-11-03')&(p.pub<='2026-07-10')]
d=c.days_to_kev.dropna(); d=d[d>=-30].clip(lower=0)
xs=np.sort(d.values); ys=np.arange(1,len(xs)+1)/len(xs)
fig,ax=plt.subplots(figsize=(6.0,2.7)); ax.plot(np.maximum(xs,0.5),ys,color=BL,lw=1.8); ax.set_xscale('log')
for h in (30,90,365): ax.axvline(h,color=GR,ls=':',lw=1); ax.text(h*1.05,0.06,f'{h} d',fontsize=8,color='#444')
ax.set_xlabel('Days from CVE publication to KEV addition (log scale, 0 d shown at 0.5)'); ax.set_ylabel('Cumulative share of KEV entries'); ax.set_ylim(0,1.02)
fig.tight_layout(); fig.savefig(out+'fig_ttk.pdf'); fig.savefig(out+'fig_ttk.png',dpi=200); plt.close()
print('ok', len(d))
