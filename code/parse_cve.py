"""Parse every CVE Record v5 JSON file in a cvelistV5 checkout into one flat table (parquet).
Separates what the CNA published (container 'cna') from what later enrichers added ('adp')."""
import json, os, sys, re, glob
from multiprocessing import Pool
from urllib.parse import urlparse
import pandas as pd
ROOT = sys.argv[1] if len(sys.argv) > 2 else None; OUT = sys.argv[2] if len(sys.argv) > 2 else None
def dom(u):
    try: return urlparse(u).netloc.lower().removeprefix('www.')
    except Exception: return ''
def cvss(metrics, tag):
    for m in metrics or []:
        if tag in m: return m[tag].get('vectorString'), m[tag].get('baseScore')
    return None, None
def parse(path):
    try: r = json.load(open(path, encoding='utf8'))
    except Exception: return None
    return parse_record(r)
def parse_record(r):
    md = r.get('cveMetadata', {}); st = md.get('state')
    row = dict(cve=md.get('cveId'), state=st, assigner=md.get('assignerShortName'), reserved=md.get('dateReserved'),
               published=md.get('datePublished'), updated=md.get('dateUpdated'))
    if st != 'PUBLISHED': return row
    c = r['containers']['cna']
    row['public_date'] = c.get('datePublic'); row['title'] = c.get('title')
    ds = [d.get('value', '') for d in c.get('descriptions', []) if str(d.get('lang', '')).lower().startswith('en')]
    row['desc'] = ds[0] if ds else ''
    cw = []
    for pt in c.get('problemTypes', []):
        for d in pt.get('descriptions', []):
            if d.get('cweId'): cw.append(d['cweId'])
            else:
                m = re.search(r'CWE-\d+', d.get('description', '') or '')
                if m: cw.append(m.group(0))
    row['cwes'] = ' '.join(sorted(set(cw)))
    aff = c.get('affected', []) or []
    row['vendors'] = ' | '.join(sorted({str(a.get('vendor', '')).lower() for a in aff}))[:300]
    row['products'] = ' | '.join(sorted({str(a.get('product', '')).lower() for a in aff}))[:300]
    row['n_affected'] = len(aff); row['has_cpe'] = int(bool(c.get('cpeApplicability')))
    refs = c.get('references', []) or []
    row['n_refs'] = len(refs); row['ref_domains'] = ' '.join(sorted({dom(x.get('url', '')) for x in refs}))
    row['ref_tags'] = ' '.join(sorted({t for x in refs for t in x.get('tags', [])}))
    row['ref_kev_cna'] = int(any('known-exploited-vulnerabilities' in x.get('url', '') for x in refs))
    row['ref_urls'] = ' '.join(x.get('url', '') for x in refs)[:2000]
    mt = c.get('metrics', []) or []
    for tag, name in [('cvssV2_0', 'v2'), ('cvssV3_0', 'v30'), ('cvssV3_1', 'v31'), ('cvssV4_0', 'v40')]:
        vs, sc = cvss(mt, tag); row[f'cna_{name}_vec'] = vs; row[f'cna_{name}_score'] = sc
    adps = r['containers'].get('adp', []) or []
    row['adp_names'] = ' '.join(a.get('providerMetadata', {}).get('shortName', '') for a in adps)
    row['n_adp'] = len(adps)
    row['adp_refs'] = sum(len(a.get('references', []) or []) for a in adps)
    row['ref_kev_adp'] = 0; row['adp_kev_date'] = None; row['ssvc_exploitation'] = None; row['ssvc_automatable'] = None; row['ssvc_impact'] = None
    for a in adps:
        for x in a.get('references', []) or []:
            if 'known-exploited-vulnerabilities' in x.get('url', ''): row['ref_kev_adp'] = 1
        for m in a.get('metrics', []) or []:
            o = m.get('other')
            if not o: continue
            if o.get('type') == 'kev': row['adp_kev_date'] = o.get('content', {}).get('dateAdded')
            if o.get('type') == 'ssvc':
                for opt in o.get('content', {}).get('options', []):
                    row['ssvc_exploitation'] = opt.get('Exploitation', row['ssvc_exploitation'])
                    row['ssvc_automatable'] = opt.get('Automatable', row['ssvc_automatable'])
                    row['ssvc_impact'] = opt.get('Technical Impact', row['ssvc_impact'])
            for tag in ('cvssV3_1', 'cvssV3_0', 'cvssV4_0'):
                if tag in m: row[f'adp_{tag}_vec'] = m[tag].get('vectorString'); row[f'adp_{tag}_score'] = m[tag].get('baseScore')
    return row
if __name__ == '__main__':
    files = sorted(glob.glob(ROOT + '/cves/*/*/CVE-*.json'))
    print(len(files), flush=True)
    with Pool(2) as p: rows = [r for r in p.imap(parse, files, chunksize=500) if r]
    df = pd.DataFrame(rows); df.to_pickle(OUT); print(df.shape, df.state.value_counts().to_dict())
