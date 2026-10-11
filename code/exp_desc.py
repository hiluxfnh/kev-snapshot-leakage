import pandas as pd, numpy as np, json, re
p = pd.read_pickle('../data/table.pkl')
c = p[(p.pub >= '2021-11-03') & (p.pub <= '2026-07-10')].copy()
c['y'] = ((c.days_to_kev <= 90) & c.days_to_kev.notna())
c['kev_ever'] = c.added.notna()
R = {'cohort_n': len(c), 'kev_ever': int(c.kev_ever.sum()), 'y90': int(c.y.sum())}
# time to KEV
kd = c[c.kev_ever].days_to_kev
R['ttk'] = {'median': float(kd.median()), 'q25': float(kd.quantile(.25)), 'q75': float(kd.quantile(.75)), 'share_le0': float((kd <= 0).mean()), 'share_le7': float((kd <= 7).mean()), 'share_le30': float((kd <= 30).mean()),
            'share_le90': float((kd <= 90).mean()), 'share_le365': float((kd <= 365).mean()), 'share_gt365': float((kd > 365).mean())}
# leakage indicator prevalence among y (positives) vs rest
def prev(mask):
    return {'pos': float(mask[c.y].mean()), 'neg': float(mask[~c.y].mean())}
ind = {}
ind['kev_block_in_ADP'] = c.adp_kev_date.notna()
ind['kev_url_in_ADP_refs'] = c.ref_kev_adp.astype(bool)
ind['CVSS_temporal_E_present'] = c.t_E.notna()
ind['CVSS_temporal_E_F_or_H'] = c.t_E.isin(['F', 'H'])
ind['SSVC_present'] = c.ssvc_exploitation.notna()
ind['SSVC_exploitation_active'] = c.ssvc_exploitation.eq('active')
ind['SSVC_exploitation_poc'] = c.ssvc_exploitation.eq('poc')
dm = c.ref_domains.fillna('')
ind['ref_exploit_db'] = dm.str.contains('exploit-db.com')
ind['ref_packetstorm'] = dm.str.contains('packetstormsecurity')
ind['ref_github'] = dm.str.contains('github.com')
ind['ref_tag_exploit'] = c.ref_tags.fillna('').str.contains(r'\bexploit\b')
ind['ref_tag_third_party'] = c.ref_tags.fillna('').str.contains('third-party-advisory')
ind['ref_tag_vendor_advisory'] = c.ref_tags.fillna('').str.contains('vendor-advisory')
ind['desc_in_the_wild'] = c.desc.fillna('').str.contains(r'in the wild|actively exploit|being exploited|exploited in', case=False, regex=True)
ind['updated_after_30d'] = c.upd_lag_days > 30
ind['updated_after_180d'] = c.upd_lag_days > 180
R['indicators'] = {k: prev(v) for k, v in ind.items()}
R['upd_lag_median'] = {'pos': float(c[c.y].upd_lag_days.median()), 'neg': float(c[~c.y].upd_lag_days.median())}
R['n_refs_median'] = {'pos': float(c[c.y].n_refs.median()), 'neg': float(c[~c.y].n_refs.median())}
# CVSS availability by label
R['cna_cvss_v3_present'] = prev(c.base_score.notna()); R['cna_cvss_v4_present'] = prev(c.cna_v40_vec.notna())
R['base_score_ge9'] = prev(c.base_score >= 9); R['base_score_ge7'] = prev(c.base_score >= 7)
# concentration
kv = c[c.y]
R['top_kev_vendors'] = kv.vendorProject.value_counts().head(12).to_dict()
R['top_kev_assigners'] = kv.assigner.value_counts().head(12).to_dict()
R['kev_assigner_share_top5'] = float(kv.assigner.value_counts().head(5).sum() / len(kv))
R['cohort_assigner_share_top5'] = float(c.assigner.value_counts().head(5).sum() / len(c))
R['kev_cwe_top'] = kv.cwes.fillna('').str.split().explode().value_counts().head(10).to_dict()
R['kev_ransomware'] = kv.knownRansomwareCampaignUse.value_counts().to_dict()
R['by_year'] = c.groupby(c.pub.dt.year).agg(n=('y', 'size'), y90=('y', 'sum'), v4=('cna_v40_vec', lambda s: s.notna().mean()), v3=('base_score', lambda s: s.notna().mean()), ssvc=('ssvc_exploitation', lambda s: s.notna().mean())).round(4).to_dict('index')
json.dump(R, open('../results/results_desc.json', 'w'), indent=1, default=str)
print(json.dumps(R, indent=1, default=str)[:6000])
