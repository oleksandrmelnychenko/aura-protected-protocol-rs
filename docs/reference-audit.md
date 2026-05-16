# Reference audit for Aura papers

Audit date: 2026-05-16.

Scope:
- `docs/aura-paper.tex`
- `docs/aura-paper-ua.tex`

Result:
- English paper: 33 `\bibitem` entries, 33 unique cited keys, 0 missing bibliography entries, 0 uncited bibliography entries.
- Ukrainian paper: 33 `\bibitem` entries, 33 unique cited keys, 0 missing bibliography entries, 0 uncited bibliography entries.
- External links: 32 unique URLs, all returned HTTP 200 with `curl -L` on 2026-05-16.
- Local companion reference: `docs/security-proof.tex` exists and is intentionally local, not an external URL.
- LaTeX build: both papers compile with `pdflatex`; final PDFs are 30 pages (`aura-paper.pdf`) and 36 pages (`aura-paper-ua.pdf`).

Verification commands:

```sh
for f in docs/aura-paper.tex docs/aura-paper-ua.tex; do
  rg -o '\\bibitem\{[^}]+\}' "$f" | wc -l
  perl -ne 'while(/\\cite[t|p|alp|author|year|]?\{([^}]*)\}/g){for $k (split /,/, $1){$k=~s/^\s+|\s+$//g; print "$k\n"}}' "$f" | sort -u | wc -l
done

rg -o '\\url\{[^}]+\}' docs/aura-paper.tex docs/aura-paper-ua.tex |
  sed 's/^.*\\url{//;s/}$//' |
  sort -u |
  while IFS= read -r u; do
    curl -L -A 'Mozilla/5.0 reference-audit' --connect-timeout 10 --max-time 30 \
      -o /dev/null -s -w '%{http_code} %{url_effective}\n' "$u"
  done
```

## Bibliography corrections made

| Item | Correction |
|---|---|
| `signal-pqxdh` in `docs/aura-paper.tex` | Replaced incorrect authors/revision with E. Kret and R. Schmidt, Revision 3, 2024, official Signal URL. |
| `rfc8452` in `docs/aura-paper.tex` | Added missing author A. Langley. |
| DOI/URL coverage | Added an official URL or DOI-backed URL to every external bibliography entry in both papers. |
| `shor1997` | Kept bibliographic journal metadata but used open arXiv URL because the SIAM DOI target can reject automated fetches. |
| `blanchet2016` | Kept journal metadata but used the author's INRIA publication page because the DOI target can reject automated fetches. |
| English bibliography size | Expanded from 27 to 33 cited sources by adding real, cited sources for Shor, CECPQ2, metadata privacy, and a more complete Double Ratchet analysis. |

## Link evidence

| Source | Key(s) | Evidence URL | HTTP |
|---|---|---|---|
| X3DH specification | `signal-x3dh` | https://signal.org/docs/specifications/x3dh/ | 200 |
| PQXDH specification | `signal-pqxdh` | https://signal.org/docs/specifications/pqxdh/ | 200 |
| Double Ratchet specification | `signal-double-ratchet` | https://signal.org/docs/specifications/doubleratchet/ | 200 |
| Signal post-quantum ratchets | `signal-spqr` | https://signal.org/blog/spqr/ | 200 |
| ML-KEM Braid specification | `mlkem-braid` | https://signal.org/docs/specifications/mlkembraid/ | 200 |
| Apple PQ3 design | `apple-pq3` | https://security.apple.com/blog/imessage-pq3/ | 200 |
| Stebila PQ3 analysis | `stebila-pq3` | https://www.douglas.stebila.ca/research/papers/Apple-Stebila24/ | 200 |
| Linker/Sasse/Basin PQ3 analysis | `linker-pq3` | https://www.usenix.org/conference/usenixsecurity25/presentation/linker | 200 |
| Cohn-Gordon et al. Signal analysis | `cohn-gordon2020` | https://doi.org/10.1007/s00145-020-09360-1 | 200 |
| Brendel et al. PQ X3DH | `brendel2020` | https://doi.org/10.1007/978-3-030-81652-0_16 | 200 |
| Hashimoto et al. X3DH construction | `hashimoto2021` | https://doi.org/10.1007/978-3-030-75248-4_15 | 200 |
| Alwen/Coretti/Dodis Double Ratchet | `alwen2020`, `acd2019` | https://doi.org/10.1007/978-3-030-17653-2_5 | 200 |
| Bienstock et al. complete Double Ratchet analysis | `bienstock2020` | https://doi.org/10.1007/978-3-031-15802-5_27 | 200 |
| Bienstock/Dodis/Roesler group ratcheting | `bienstock2022` | https://doi.org/10.1007/978-3-030-64378-2_8 | 200 |
| FIPS 203 ML-KEM | `fips203` | https://doi.org/10.6028/NIST.FIPS.203 | 200 |
| Shor quantum algorithms | `shor1997` | https://arxiv.org/abs/quant-ph/9508027 | 200 |
| CECPQ2 experiment | `cecpq2` | https://www.imperialviolet.org/2018/12/12/cecpq2.html | 200 |
| Stebila/Mosca OQS | `stebila2020` | https://doi.org/10.1007/978-3-319-69453-5_2 | 200 |
| Dowling et al. TLS 1.3 analysis | `dowling2020` | https://doi.org/10.1007/s00145-021-09384-1 | 200 |
| HKDF paper | `krawczyk2010` | https://doi.org/10.1007/978-3-642-14623-7_34 | 200 |
| RFC 7748 | `rfc7748` | https://www.rfc-editor.org/rfc/rfc7748 | 200 |
| RFC 5869 | `rfc5869` | https://www.rfc-editor.org/rfc/rfc5869 | 200 |
| RFC 8452 | `rfc8452` | https://www.rfc-editor.org/rfc/rfc8452 | 200 |
| RFC 9420 / MLS | `mls-rfc`, `rfc9420` | https://www.rfc-editor.org/rfc/rfc9420 | 200 |
| Canetti/Krawczyk secure channels | `canetti2001` | https://doi.org/10.1007/3-540-44987-6_28 | 200 |
| LaMacchia/Lauter/Mityagin eCK | `lamacchia2007` | https://doi.org/10.1007/978-3-540-75670-5_1 | 200 |
| Tamarin prover | `meier2013` | https://doi.org/10.1007/978-3-642-39799-8_48 | 200 |
| ProVerif survey | `blanchet2016` | https://bblanche.gitlabpages.inria.fr/publications/BlanchetFnTPS16.html | 200 |
| Rogaway/Shrimpton key-wrap | `rogaway2006` | https://doi.org/10.1007/11761679_23 | 200 |
| Signal Sealed Sender | `sealed-sender` | https://signal.org/blog/sealed-sender/ | 200 |
| Sphinx mix format | `sphinx` | https://doi.org/10.1109/SP.2009.15 | 200 |
| Loopix anonymity system | `loopix` | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska | 200 |
| Aura companion proof | `aura-security-proof` | `docs/security-proof.tex` | local file exists |

## Metadata checks

DOI-backed sources were also checked against Crossref metadata for title and venue consistency. The following high-risk entries were explicitly verified:

| Key | Verified title |
|---|---|
| `cohn-gordon2020` | A Formal Security Analysis of the Signal Messaging Protocol |
| `brendel2020` | Towards Post-Quantum Security for Signal's X3DH Handshake |
| `hashimoto2021` | An Efficient and Generic Construction for Signal's Handshake (X3DH): Post-Quantum, State Leakage Secure, and Deniable |
| `alwen2020` / `acd2019` | The Double Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol |
| `bienstock2020` | A More Complete Analysis of the Signal Double Ratchet Algorithm |
| `bienstock2022` | On the Price of Concurrency in Group Ratcheting Protocols |
| `stebila2020` | Post-quantum Key Exchange for the Internet and the Open Quantum Safe Project |
| `dowling2020` | A Cryptographic Analysis of the TLS 1.3 Handshake Protocol |
| `krawczyk2010` | Cryptographic Extraction and Key Derivation: The HKDF Scheme |
| `canetti2001` | Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels |
| `lamacchia2007` | Stronger Security of Authenticated Key Exchange |
| `meier2013` | The TAMARIN Prover for the Symbolic Analysis of Security Protocols |
| `rogaway2006` | A Provable-Security Treatment of the Key-Wrap Problem |
| `sphinx` | Sphinx: A Compact and Provably Secure Mix Format |
