"""Find, for every CVE file, the first commit that added it (CVE List repo history) and keep the CVEs whose first commit is within 2 days of
the publication date. Needs raw/cvelistV5 (blobless full-history clone) and data/added_raw.txt from:
  git -C raw/cvelistV5 log --no-renames --diff-filter=A --raw --no-abbrev --since=2023-03-29 --format='C %H %aI' -- cves > data/added_raw.txt
Writes ../data/first_add2.pkl, ../data/hist_cohort.pkl and ../data/oids.txt (blob ids to fetch with: git fetch origin --filter=blob:none <oids>)."""
import pandas as pd, re
rows = []; cur = None
for l in open('../data/added_raw.txt'):
    if l.startswith('C '): _, h, d = l.split(); cur = (h, d)
    elif l.startswith(':'):
        a, path = l.rstrip('\n').split('\t'); oid = a.split()[3]
        m = re.search(r'(CVE-\d+-\d+)\.json$', path)
        if m: rows.append((m.group(1), path, oid, cur[0], cur[1]))
f = pd.DataFrame(rows, columns=['cve', 'path', 'oid', 'commit', 'added_at']); f['added_at'] = pd.to_datetime(f.added_at, utc=True).dt.tz_localize(None)
f = f.sort_values('added_at').drop_duplicates('cve')
t = pd.read_pickle('../data/table.pkl')
m = t.merge(f, on='cve'); m['lag'] = (m.added_at - pd.to_datetime(m.published, utc=True).dt.tz_localize(None)).dt.total_seconds() / 86400
m[['cve', 'path', 'oid', 'commit', 'added_at', 'lag']].to_pickle('../data/first_add2.pkl')
m = m[m.lag.abs() < 2]; m = m[(m.pub >= '2023-04-01') & (m.pub <= '2026-07-10')]
m.to_pickle('../data/hist_cohort.pkl'); m[['oid']].drop_duplicates().to_csv('../data/oids.txt', index=False, header=False); print(len(m))
