# Where to submit: journals and free-to-submit conferences

Prepared 10 October 2026 for the paper "What the Record Remembers: Snapshot Leakage in Predicting Exploited Vulnerabilities from Public CVE Data".

## How to read this guide

"Free to submit" means the venue charges nothing to submit or review a paper. It does not mean attending is free. If a paper is accepted, at least one author usually has to register (and often present), and registration can cost several hundred dollars or more. Look for student grants, volunteer programmes and virtual-attendance options on each conference page. Where I could not read a publisher's page myself, I say "confirm on the author page" rather than guess.

Deadlines below come from the security-conference deadline tracker at sec-deadlines.github.io (page updated 7 October 2026) unless I say otherwise. Deadlines move, so check the official call before you plan around one.

One practical caveat: you study in Saint Petersburg. Publisher and conference policies about authors affiliated with Russian institutions, and the practical ability to pay registration fees from Russia, vary. Check each venue's policy and ask the organisers before you submit.

## Conferences and workshops (submission free; check dates)

| Venue | Deadline | Why it fits | Notes |
|---|---|---|---|
| AI-SEC 2027 (3rd International Workshop on AI for Cybersecurity, a track of AINA-2027) | 10 Dec 2026 | Best match for deadline and scope: machine learning applied to security | Official page: 10 pages including references, Springer Lecture Notes format, Scopus-indexed, at least one author must register and present. Fees not stated on the page. |
| CODASPY 2027 (ACM Conference on Data and Application Security and Privacy) | 23 Nov 2026 | Data-driven security, strong fit for a data-quality and evaluation paper | Main-track, selective. Check page limit and whether a short-paper category exists. |
| IEEE EuroS&P 2027 | 2 Dec 2026 | Top-tier general venue; the paper is closer to a measurement-and-methodology contribution than usual for it | Very selective. Its co-located workshops usually have later deadlines (not yet verified). |
| DSN 2027 (Dependable Systems and Networks) | 2 Dec 2026 | Dependability and evaluation methodology | Check which track suits a data-analysis paper. |
| ASIA CCS 2027 | 11 Dec 2026 | General security, ACM | Selective. |
| ISDFS 2027 (International Symposium on Digital Forensics and Security) | 31 Jan 2027 | Realistic target for a first conference paper | Check indexing on the official site. |
| SECRYPT 2027 | 16 Feb 2027 (and 25 Mar 2027 for a second round) | Security and cryptography, SCITEVENTS series | Check proceedings indexing and fees before choosing. |
| ICICS 2027 | 28 Feb 2027 (and 30 May 2027) | Information and communications security, Springer LNCS | Check which of the two dates is for which round. |
| USENIX Security 2027 | 26 Jan 2027 | Top tier; worth considering only after strengthening the paper (see below) | Very selective. |
| IEEE S&P 2027 | 17 Nov 2026 | Top tier | Too soon and too selective for this draft. |

Venues I looked for but could not fully confirm: the ACM AISec workshop (held with CCS) and the IEEE S&P and EuroS&P workshops for 2027. Their calls for 2027 had not been fetched successfully when I wrote this. Their deadlines usually fall in the summer or early spring; check the official sites around those months. The S&P 2027 workshop call is at sp2027.ieee-security.org/cfworkshops.html (blocked to my tools).

Other low-cost routes: post the paper on arXiv (cs.CR) before or at submission if the venue allows preprints; this gives you a citable record for PhD applications right away.

## Journals

Journals have no deadline, so a finished paper can go in at any time. Fee details are not verified; confirm each on the journal's author page. Subscription-route publication in Elsevier, Springer and ACM journals is generally free to the author, with an optional paid open-access choice, but verify this for your chosen journal and funding situation.

| Journal | Publisher | Why it fits |
|---|---|---|
| Computers & Security | Elsevier | Well-known applied security journal that publishes empirical studies. |
| Journal of Information Security and Applications (JISA) | Elsevier | Applied security and machine learning for security. |
| ACM Digital Threats: Research and Practice (DTRAP) | ACM | ACM journal aimed at practical work on digital threats; the topic (vulnerability prioritization) is in scope, but confirm its current scope statement. |
| IEEE Transactions on Information Forensics and Security | IEEE | Highly selective; consider after a stronger revision. |
| IEEE Transactions on Dependable and Secure Computing | IEEE | Highly selective; related prior work (Anwar et al.) appeared here. |
| International Journal of Information Security | Springer | Solid mid-tier option. |
| Journal of Cybersecurity | Oxford University Press | Open-access, interdisciplinary; usually involves an article processing charge, so confirm. |

## How to make the paper competitive for the stronger venues

The draft is honest about its limits, and most of them are things a reviewer will raise. In rough priority order:

1. Rebuild each CVE record as it looked on the day of disclosure, using the commit history of the CVE List repository. This replaces the "inferred timing" limitation with a measurement and would be the strongest single upgrade.
2. Add a second model family (gradient boosting) and, if you can obtain historical EPSS scores, an EPSS comparison.
3. Add several random seeds or repeated splits and report variation.
4. Add a second ground truth, for example Exploit-DB or a vendor-reported exploitation flag, to address the limits of KEV as a label.

## Before you submit

- Read the paper in full and rerun the code. Regenerating all numbers takes a few hours on a laptop.
- Declare AI use in the submission portal's own field, not in the paper, and check the venue's AI policy first. Some venues require specific wording or forbid listing an AI system as an author.
- Add your email and any co-author or supervisor names. A supervisor reading the draft before submission is wise.
- Use the anonymous PDF for venues with double-blind review, and the named PDF otherwise.
