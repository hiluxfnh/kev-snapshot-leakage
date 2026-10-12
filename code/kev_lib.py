import numpy as np, pandas as pd, scipy.sparse as sp
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

CAT_BASE = ['b_AV', 'b_AC', 'b_PR', 'b_UI', 'b_S', 'b_C', 'b_I', 'b_A', 'v4_AV', 'v4_AC', 'v4_AT', 'v4_PR', 'v4_UI', 'v4_VC', 'v4_VI', 'v4_VA', 'v4_SC', 'v4_SI', 'v4_SA']
GROUPS = {
    'S': 'disclosure-time safe: CNA base CVSS, CWE, affected vendors/products, CNA, text, counts, reserve-to-publish lag',
    'C_temporal': 'CVSS temporal metrics (E, RL, RC) in CNA vector',
    'C_refs': 'reference domains, reference tags, reference count',
    'C_update': 'record update lag (updated minus published)',
    'C_enrich': 'ADP enrichment: number of ADP containers, provider names, SSVC options, ADP references',
    'C_kevfield': 'CISA-ADP kev block and KEV reference',
}
def tok_space(s): return s.split()
def tok_bar(s): return [t.strip() for t in s.split('|') if t.strip()]

def _bin(df, col, tok, min_df):
    try: return CountVectorizer(tokenizer=tok, lowercase=False, binary=True, min_df=min_df, token_pattern=None).fit(df[col].fillna('').astype(str))
    except ValueError: return CountVectorizer(vocabulary=['__none__'], tokenizer=tok, lowercase=False, binary=True, token_pattern=None)  # field empty in all training records

class Feat:
    """Fit on a training frame only; transform any frame. groups: iterable of group names (always include 'S')."""
    def __init__(self, groups, text=True): self.groups = set(groups) | {'S'}; self.text = text
    def _num(self, d):
        cols = {}
        cols['base_score'] = d.base_score.fillna(0); cols['has_base'] = d.base_score.notna().astype(float)
        cols['v2'] = d.cna_v2_vec.notna().astype(float); cols['v4'] = d.cna_v40_vec.notna().astype(float)
        cols['n_aff'] = np.log1p(d.n_affected); cols['has_cpe'] = d.has_cpe.astype(float); cols['n_cwe'] = d.n_cwe
        cols['desc_len'] = np.log1p(d.desc.fillna('').str.len()); cols['res_lag'] = np.log1p((d.pub - d.res).dt.days.clip(lower=0).fillna(0))
        if 'C_refs' in self.groups: cols['n_refs'] = np.log1p(d.n_refs)
        if 'C_update' in self.groups: cols['upd_lag'] = np.log1p(d.upd_lag_days.clip(lower=0).fillna(0))
        if 'C_enrich' in self.groups: cols['n_adp'] = d.n_adp.astype(float); cols['adp_refs'] = np.log1p(d.adp_refs)
        if 'C_kevfield' in self.groups: cols['kevblock'] = d.adp_kev_date.notna().astype(float); cols['kevref'] = ((d.ref_kev_adp + d.ref_kev_cna) > 0).astype(float)
        return pd.DataFrame(cols)
    def _cats(self, d):
        c = d[CAT_BASE + ['assigner']].copy()
        if 'C_temporal' in self.groups: c['t_E'] = d.t_E; c['t_RL'] = d.t_RL; c['t_RC'] = d.t_RC; c['v4_E'] = d.v4_E
        if 'C_enrich' in self.groups: c['ssvc_e'] = d.ssvc_exploitation; c['ssvc_a'] = d.ssvc_automatable; c['ssvc_i'] = d.ssvc_impact
        return c.fillna('NA').astype(str)
    def fit(self, d):
        self.sc = StandardScaler().fit(self._num(d)); self.oh = OneHotEncoder(handle_unknown='ignore', min_frequency=5).fit(self._cats(d))
        self.cv = {'cwes': _bin(d, 'cwes', tok_space, 5), 'vendors': _bin(d, 'vendors', tok_bar, 3), 'products': _bin(d, 'products', tok_bar, 3)}
        if 'C_refs' in self.groups: self.cv['ref_domains'] = _bin(d, 'ref_domains', tok_space, 5); self.cv['ref_tags'] = _bin(d, 'ref_tags', tok_space, 5)
        if 'C_enrich' in self.groups: self.cv['adp_names'] = _bin(d, 'adp_names', tok_space, 5)
        if self.text: self.tf = TfidfVectorizer(ngram_range=(1, 2), min_df=5, max_features=30000, sublinear_tf=True, stop_words='english').fit((d.title.fillna('') + ' . ' + d.desc.fillna('')))
        return self
    def transform(self, d):
        parts = [sp.csr_matrix(self.sc.transform(self._num(d))), self.oh.transform(self._cats(d))]
        for k, v in self.cv.items(): parts.append(v.transform(d[k].fillna('').astype(str)).astype(np.float32))
        if self.text: parts.append(self.tf.transform(d.title.fillna('') + ' . ' + d.desc.fillna('')))
        return sp.hstack(parts, format='csr')

def metrics(y, s, rng=None, n_boot=0):
    y = np.asarray(y); s = np.asarray(s); n = len(y); pos = int(y.sum())
    order = np.argsort(-s, kind='stable'); ys = y[order]
    def at(frac): k = max(1, int(round(frac * n))); return float(ys[:k].sum() / k), float(ys[:k].sum() / max(pos, 1))
    out = dict(n=n, pos=pos, auc=float(roc_auc_score(y, s)) if 0 < pos < n else np.nan, ap=float(average_precision_score(y, s)) if pos else np.nan)
    out['prec_top1'], out['rec_top1'] = at(0.01); out['prec_top5'], out['rec_top5'] = at(0.05)
    if n_boot and rng is not None and 0 < pos < n:
        a = []; b = []
        for _ in range(n_boot):
            i = rng.integers(0, n, n)
            if y[i].sum() == 0: continue
            a.append(roc_auc_score(y[i], s[i])); b.append(average_precision_score(y[i], s[i]))
        out['auc_ci'] = [float(np.quantile(a, .025)), float(np.quantile(a, .975))]; out['ap_ci'] = [float(np.quantile(b, .025)), float(np.quantile(b, .975))]
    return out
