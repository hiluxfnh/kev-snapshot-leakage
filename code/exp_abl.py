import numpy as np, pandas as pd, json, re, warnings
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from kev_lib import *
H=90; p=pd.read_pickle('../data/table.pkl')
c=p[(p.pub>='2021-11-03')&(p.pub<='2026-07-10')].copy().reset_index(drop=True)
c['y']=((c.days_to_kev<=H)&c.days_to_kev.notna()).astype(int)
pat=re.compile(r'(exploited|exploitation|in the wild|actively|known to be|observed|proof[- ]of[- ]concept|public exploit|being exploited|attacks?)',re.I)
c['desc_s']=c.desc.fillna('').apply(lambda s: pat.sub(' ',s)); c['title_s']=c.title.fillna('').apply(lambda s: pat.sub(' ',s))
print('desc changed share pos',(c.desc!=c.desc_s)[c.y==1].mean(),'neg',(c.desc!=c.desc_s)[c.y==0].mean(),flush=True)
rng=np.random.default_rng(0); out=[]
for Y in (2024,2025,2026):
    t0=pd.Timestamp(f'{Y}-01-01'); t1=pd.Timestamp(f'{Y+1}-01-01')
    te=c.index[(c.pub>=t0)&(c.pub<t1)]; tr=c.index[c.pub<=t0-pd.Timedelta(days=H)]
    for name,txt,scrub in (('S',True,False),('S_scrubbed',True,True),('S_no_text',False,False)):
        d=c.copy()
        if scrub: d['desc']=d.desc_s; d['title']=d.title_s
        f=Feat([],text=txt).fit(d.loc[tr]); m=LogisticRegression(solver='liblinear',C=1.0,max_iter=200).fit(f.transform(d.loc[tr]),d.y[tr])
        r=metrics(d.y[te],m.decision_function(f.transform(d.loc[te])),rng,200); r.update(cfg=name,test=Y); out.append(r); print(Y,name,round(r['auc'],3),round(r['ap'],3),flush=True)
        json.dump(out,open('../results/results_ablation_H90.json','w'),default=float)
