import numpy as np, pandas as pd, json
from kev_lib import metrics
H=90; p=pd.read_pickle('../data/table.pkl')
c=p[(p.pub>='2021-11-03')&(p.pub<='2026-07-10')].copy().reset_index(drop=True)
c['y']=((c.days_to_kev<=H)&c.days_to_kev.notna()).astype(int)
rng=np.random.default_rng(0); out=[]
c['bs']=c.base_score.fillna(-1)
c['nvd_easy']=((c.b_AV=='N')&(c.b_AC=='L')&(c.b_PR=='N')&(c.b_UI=='N')).astype(int)
c['vend']=c.vendors.apply(lambda v: (list(v)[0] if len(v) else '') if hasattr(v,'__len__') and not isinstance(v,str) else str(v))
for Y in (2024,2025,2026):
    t0=pd.Timestamp(f'{Y}-01-01'); t1=pd.Timestamp(f'{Y+1}-01-01')
    te=c[(c.pub>=t0)&(c.pub<t1)]; tr=c[c.pub<=t0-pd.Timedelta(days=H)]
    rate=tr.groupby('vend').y.agg(['sum','count']); prior=tr.y.mean()
    def vp(v): 
        if v in rate.index: s,n=rate.loc[v]; return (s+prior*5)/(n+5)
        return prior
    sc={'cvss_ge9':(te.bs>=9).astype(float)+te.bs/100,'cvss_ge7':(te.bs>=7).astype(float)+te.bs/100,
        'cvss_score':te.bs,'network_easy_vector':te.nvd_easy+te.bs/100,'vendor_prior':te.vend.map(vp).astype(float)}
    for k,s in sc.items():
        r=metrics(te.y.values,np.asarray(s),rng,200); r.update(rule=k,test=Y,H=H); out.append(r); print(Y,k,round(r['auc'],3),round(r['ap'],3),r['pos'])
json.dump(out,open('../results/results_baselines_H90.json','w'),default=float)
