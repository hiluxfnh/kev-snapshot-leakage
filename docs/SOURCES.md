# Data sources and exact versions

The raw inputs are public GitHub repositories. They are not stored here because they are large. Clone them into `raw/` at the commits below to reproduce the paper exactly.

| Folder in raw/ | Repository | Commit | Commit date (UTC) |
|---|---|---|---|
| cvelistV5 | https://github.com/CVEProject/cvelistV5 | 1fe0ac3e4e575b04743b7da015af15591cda7fae | 2026-10-10 |
| vulnrichment | https://github.com/cisagov/vulnrichment | 4bee85052dbf292bc600db4359e4d2cc577859ac | 2026-10-10 |
| kev-data | https://github.com/cisagov/kev-data | be330da604b41a3b29c84b3f0a0122d6d2167417 | 2026-10-08 |

The KEV file used is `raw/kev-data/known_exploited_vulnerabilities.json` (catalog version 2026.10.08, 1,739 entries).

The clones were shallow (`git clone --depth 1`), so cloning the latest commit gives you newer data and slightly different numbers. To match the paper, fetch the exact commit:

    git clone https://github.com/CVEProject/cvelistV5 raw/cvelistV5
    git -C raw/cvelistV5 checkout 1fe0ac3e4e575b04743b7da015af15591cda7fae

(repeat for the other two).

Licensing of the data follows each source: the CVE List is published under the CVE Program terms of use, and the CISA repositories are US government works. Check their pages before redistributing the derived table commercially.
