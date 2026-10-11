# Derived table: data/cohort_2021-11-03_to_2026-10_derived.csv.xz

One row per CVE published on or after 2021-11-03 (221,931 rows). It is a subset of the columns that `code/prep.py` builds. List-valued fields use spaces or the bar character as separators, as in the code.

| Column | Meaning | Feature group in the paper |
|---|---|---|
| cve | CVE ID | key |
| assigner | CNA that assigned the ID | S |
| reserved, published, updated | raw timestamps from the record (updated is the snapshot value) | reserved/published used by S; updated feeds C_update |
| pub, upd, res | parsed UTC timestamps | as above |
| title, desc | CNA title and description | S (text) |
| cwes, vendors, products, n_affected, has_cpe, n_cwe | weakness and affected-product fields | S |
| base_score, b_AV, b_AC, b_PR, b_UI, b_S, b_C, b_I, b_A | CNA base CVSS v3 components | S |
| cna_v31_vec, cna_v40_vec | CNA CVSS vectors | S (components) |
| t_E, t_RL, t_RC, v4_E | CVSS temporal and v4 exploit maturity | C_temporal |
| n_refs, ref_domains, ref_tags | references | C_refs |
| upd_lag_days | days between published and last update | C_update |
| n_adp, adp_names, adp_refs, ssvc_exploitation, ssvc_automatable, ssvc_impact | enrichment container fields | C_enrich |
| adp_kev_date | CISA kev block date in the record | C_kevfield (direct label leak) |
| added | KEV dateAdded, empty if never listed | label source |
| days_to_kev | added minus pub in days (negative or zero means on or before publication) | label source |

The 90-day label is `days_to_kev <= 90`. The cohort for horizon H ends H days before 2026-10-08, as described in the paper.

To rebuild the full 70-column table from raw data, run `code/parse_cve.py` and `code/prep.py`.
