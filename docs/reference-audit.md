# Reference Audit for Aura Papers

Audit date: 2026-05-18.

Scope:
- `docs/aura-paper.tex`
- `docs/aura-paper-ua.tex`

Result:
- English paper: 33 `\bibitem` entries, 33 unique cited keys, 0 missing entries, 0 uncited entries.
- Ukrainian paper: 33 `\bibitem` entries, 33 unique cited keys, 0 missing entries, 0 uncited entries.
- External links: 33 unique URLs; all returned HTTP 200 with `curl -L` on 2026-05-18.
- Paper build: `./scripts/reproduce-paper-artifact.sh paper` compiled both PDFs with `pdflatex`; generated output was 31 pages for `aura-paper.pdf` and 36 pages for `aura-paper-ua.pdf`.

Verification commands:

```sh
./scripts/audit-paper-references.sh
./scripts/reproduce-paper-artifact.sh paper
```

The reference checker extracts all `\bibitem` keys, extracts all `\cite{...}` keys, fails on missing or uncited entries, then checks every unique `\url{...}` with:

```sh
curl -L -A 'Mozilla/5.0 reference-audit' \
  --connect-timeout 10 --max-time 30 \
  --retry 2 --retry-delay 1
```

## Bibliography Corrections

| Item | Correction |
|---|---|
| Melnychenko coauthored sources | Added the three coauthored infrastructure/UAV references used in the OPAQUE manuscript to both Aura papers. |
| Local self-reference | Removed the companion proof entry from both bibliographies and from the citation flow. |
| Group-protocol sources | Removed group-protocol references from the current two-party paper scope. |
| URL coverage | Kept every cited bibliography entry backed by a URL that returns HTTP 200 in the audit. |

## Link Evidence

| Key(s) | Evidence URL | HTTP |
|---|---|---|
| `svystun2025dytam` | https://api.crossref.org/works/10.3390/en18071823 | 200 |
| `svystun2024thermal` | https://doi.org/10.47839/ijc.23.4.3752 | 200 |
| `lysyi2025fire` | https://doi.org/10.32620/reks.2025.2.06 | 200 |
| `signal-x3dh` | https://signal.org/docs/specifications/x3dh/ | 200 |
| `signal-pqxdh` | https://signal.org/docs/specifications/pqxdh/ | 200 |
| `signal-double-ratchet` | https://signal.org/docs/specifications/doubleratchet/ | 200 |
| `signal-spqr` | https://signal.org/blog/spqr/ | 200 |
| `mlkem-braid` | https://signal.org/docs/specifications/mlkembraid/ | 200 |
| `apple-pq3` | https://security.apple.com/blog/imessage-pq3/ | 200 |
| `stebila-pq3` | https://www.douglas.stebila.ca/research/papers/Apple-Stebila24/ | 200 |
| `linker-pq3` | https://www.usenix.org/conference/usenixsecurity25/presentation/linker | 200 |
| `cohn-gordon2020` | https://doi.org/10.1007/s00145-020-09360-1 | 200 |
| `brendel2020` | https://doi.org/10.1007/978-3-030-81652-0_16 | 200 |
| `hashimoto2021` | https://doi.org/10.1007/978-3-030-75248-4_15 | 200 |
| `alwen2020`, `acd2019` | https://doi.org/10.1007/978-3-030-17653-2_5 | 200 |
| `bienstock2020` | https://doi.org/10.1007/978-3-031-15802-5_27 | 200 |
| `fips203` | https://doi.org/10.6028/NIST.FIPS.203 | 200 |
| `shor1997` | https://arxiv.org/abs/quant-ph/9508027 | 200 |
| `cecpq2` | https://www.imperialviolet.org/2018/12/12/cecpq2.html | 200 |
| `stebila2020` | https://doi.org/10.1007/978-3-319-69453-5_2 | 200 |
| `dowling2020` | https://doi.org/10.1007/s00145-021-09384-1 | 200 |
| `krawczyk2010` | https://doi.org/10.1007/978-3-642-14623-7_34 | 200 |
| `rfc7748` | https://www.rfc-editor.org/rfc/rfc7748 | 200 |
| `rfc5869` | https://www.rfc-editor.org/rfc/rfc5869 | 200 |
| `rfc8452` | https://www.rfc-editor.org/rfc/rfc8452 | 200 |
| `canetti2001` | https://doi.org/10.1007/3-540-44987-6_28 | 200 |
| `lamacchia2007` | https://doi.org/10.1007/978-3-540-75670-5_1 | 200 |
| `meier2013` | https://doi.org/10.1007/978-3-642-39799-8_48 | 200 |
| `blanchet2016` | https://bblanche.gitlabpages.inria.fr/publications/BlanchetFnTPS16.html | 200 |
| `rogaway2006` | https://doi.org/10.1007/11761679_23 | 200 |
| `sealed-sender` | https://signal.org/blog/sealed-sender/ | 200 |
| `sphinx` | https://doi.org/10.1109/SP.2009.15 | 200 |
| `loopix` | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska | 200 |
