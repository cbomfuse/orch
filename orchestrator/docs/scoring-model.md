# Scoring model (version 1.1)

`SCORING_MODEL_VERSION` in `orchestrator/__init__.py` is bumped whenever any rule below changes, and
every output carries it, so 2CBOM can refuse priors produced by a model it does not understand.
Version 1.1 adds the rules for **artifact cases** (certificates, keys, keystores and configuration files,
whose ground-truth occurrences are marked `fileLevel`) and compares certificates by identity; on the five
program cases it reproduces version 1.0 except that a certificate detection whose reported subject,
issuer or validity all belong to another certificate is no longer credited (see the changes at the end).

## 1. Matching detections to ground-truth assets

Matching is done per asset type.

### Algorithms

1. **Compatibility.** A detection is a candidate for a ground-truth algorithm when their lexicon
   families agree (`aes`, `rsa`, `sha2`, `ml-kem`, …).  The generic family `ec` is compatible with
   `ecdsa`/`ecdh`/`eddsa` at half credit.  An OID equal to the asset's OID makes the detection a
   candidate regardless of the name; an OID that several assets of the case share (`rsaEncryption`
   for every RSA key size, `id-ecPublicKey` for every curve) names the family only, so it does not
   override a conflicting parameter set.  Detections whose name cannot be parsed fall back to an exact
   (normalised) name/id comparison.
2. **Identity score.** The asset's *discriminating slots* are its descriptor slots that are not
   null (family, parameter set, mode, padding, curve, hash; `other` values are not discriminating).
   For each slot the detection either matches (+1), conflicts (−1) or is missing (0); the identity
   score is the clipped sum divided by the number of slots.  `AES` vs `aes-256-gcm` → 1/3;
   `AES-128-GCM` vs `aes-256-gcm` → (1 − 1 + 1)/3 = 1/3 with a `parameterSetIdentifier` conflict;
   OID match → 1.
3. **Location.** Reported occurrences hit an asset when the line lies within `line_tolerance`
   (default 1) of one of the asset's occurrence spans in the same file (paths compared by suffix,
   so mount prefixes such as `/github/workspace/` do not matter).  Occurrences the corpus marks
   `fileLevel` (artifact files: a PEM block, a certificate inside a PKCS#7 or keystore, a
   configuration line) are also hit by a location that names the file when either side has no line —
   scanners report certificates and keys by path, and DER files and keystores have no lines.
4. **Assignment.**
   * *Located* candidates (at least one overlapping occurrence) all receive the detection — a tool
     that emits one `AES` component whose occurrences span the GCM and CBC call sites has found both.
     When the hits rest on `fileLevel` evidence, only the best-scoring located candidates receive it:
     one certificate file holds its key algorithm and its signature algorithm, both RSA, and a bare
     `RSA` there is the key.
   * A detection that points into an **artifact file** (one with `fileLevel` occurrences or non-asset
     mentions) where no compatible asset occurs is a false positive, not an imprecise location; it
     can still be an *implicit* asset (Ed25519's SHA-512), which never has a location.
   * If the detection has locations but none overlap a compatible asset, and a location is a line the
     corpus marks as a **non-asset mention** of the same name (a comment, a string), the detection is a
     **lexical false positive**.
   * Otherwise the detection goes to the single best candidate by identity score, preferring
     explicit over implicit assets and less specific over more specific ones; ties are flagged
     `ambiguous`.

Match levels: `oid`, `exact` (every slot matched), `partial`, `family` (only the family), `name`.

### Related crypto material

Candidates must have a compatible material type (`secret-key` = `secret-key`, `other` = `other` for
the CSR and CRL objects CycloneDX has no type for; `key` covers all key types at 0.75;
`nonce`/`initialization-vector` and `salt`/`seed` are near-synonyms at 0.75/0.5).  Secret scanners
type a finding by the rule that fired (`generic-api-key` → `key`), so `password`, `credential`,
`token`, `key` and `secret-key` are compatible at 0.2 — but only for a detection located on the asset.  The
score adds the agreement of the referenced algorithm (resolved through `algorithmRef`, compared slot
by slot against the ground-truth algorithm the material belongs to) and the size (bits, or bytes×8).
Location rules are the same as for algorithms; among located candidates only the best-scoring ones
are kept, which is what separates the X25519 shared secret from the ECDH one on adjacent lines.

### Certificates, protocols, libraries

Certificates match by identity: the type counts 1, and each identifying attribute the tool reports —
subject, issuer (as distinguished names, order and spelling ignored; a common name alone identifies a
certificate when it is right), `notValidBefore`, `notValidAfter` (as instants) — counts +1 when it
agrees and −1 when it does not, over 1 + the number reported.  Attributes a tool leaves out do not
count, so a bare "certificate here" scores 1.  A detection whose identity score is 0 is not that
certificate, and among located certificates only the best-scoring ones receive the detection (a chain
bundle or keystore holds several).  Protocols match by protocol type with version agreement; libraries match by purl (type/namespace/name, version ignored), by purl name, or by
normalised component name against the corpus library's name/id.

## 2. Attribute outcomes

For the **best** matching detection of each detected asset (highest identity score, then most
overlapping occurrences) every ground-truth attribute with a value yields `expected`, `reported`
(normalised) and `correct` ∈ [0, 1]:

| Asset type | Attributes |
|---|---|
| algorithm | `primitive`, `parameterSetIdentifier`, `mode`, `padding`, `curve`, `cryptoFunctions` (Jaccard), `oid`, `classicalSecurityLevel`, `nistQuantumSecurityLevel` |
| related-crypto-material | `type`, `size`, `algorithmRef` (slot agreement with the referenced ground-truth algorithm) |
| certificate | `subjectName`, `issuerName` (Jaccard over attribute/value pairs: a CN-only report of a three-attribute DN scores 1/3), `signatureAlgorithmRef` (resolved through the referenced component's name and properties), `subjectPublicKeyRef`, `certificateFormat` (+ validity dates, compared as instants, when the corpus states literal values) |
| protocol | `type`, `version`, `cipherSuites` (Jaccard) |
| library | `purl`, `version` |
| every type | `identity` — pseudo-attribute whose `correct` is the identity score, so 2CBOM can ask about identity conflicts |

Values encoded in the name count as reported (`AES-256-GCM` reports the parameter set and the mode even
if `algorithmProperties` is empty) because 2CBOM derives the same slots from the name.  A curve that
the lexicon *assumed* from a key size (`ECDSA` + `256` → P-256) counts for identity but not as a
reported `curve`.  `pkcs5` ≡ `pkcs7`; `pss` ≡ the corpus' `other`; `"256"` ≡ `P-256`.

Per detected asset: `completeness` = reported / expected attributes, `correctness` = mean `correct`
over reported attributes.

## 3. Ledger rows and categories

Every (tool, case, asset) is a row with facets: `language`, `case`, `assetType`, `subtype`
(primitive / material type / protocol type / `library`), `family`, `scenarios`, `libraries`,
`implicit`, `pqc`.  Unmatched detections are `fp` rows with the facets they *reported*.

A **category** is any set of facet values.  Rows are filtered, so a category that was never
precomputed can be scored exactly from `scorecard.json`.  The precomputed combinations
(`FACET_COMBOS`) are the facets alone and the pairs `language×assetType`, `language×subtype`,
`language×family`, `assetType×subtype`, `language×assetType×subtype`, `language×scenario`,
`language×pqc`.

## 4. Category metrics

| Metric | Definition |
|---|---|
| `recall` | detected assets / assets in the category |
| `precision` | matched detections / (matched detections + false positives whose reported facets fall in the category) |
| `completeness` | mean completeness over detected assets |
| `correctness` | mean correctness over detected assets |
| `locality` | mean (matched spans / expected spans) over detected, non-implicit, non-library assets; for artifact cases a span is one place an asset is stored (a PEM block, a keystore entry), so a certificate in four files that a tool reports in two has locality 0.5 |
| `identity` | mean identity score over detected assets |
| `score` | Σ wᵢ·metricᵢ with weights `recall 0.35, precision 0.15, completeness 0.15, correctness 0.25, locality 0.10` (renormalised when a metric is undefined) |
| `scoreShrunk` | score shrunk toward the tool's overall score with prior weight `shrinkage_prior_weight` (5) — use it for tiny categories |
| `attributes.<name>` | expected / reported / correct counts, completeness and correctness per attribute |

Runs with status `unsupported` or `failed` are **not** scored (no evidence) unless
`scoring.treat_failed_as_zero` is set; `coverage` in the scorecard shows them.

**2CBOM trust** = round(100 · overall score) clamped to `[trust_floor, trust_ceiling]`.
**2CBOM strengths** = attributes with correctness ≥ `strength_threshold` (0.8), completeness ≥ 0.5 and
at least `strength_min_support` (5) reports.

## 5. Head-to-head tables

For two tools, over assets both scanned: counts of assets only A found, only B found, both missed; and
per attribute (when both reported it) `agree`, `agreeWrong`, `aWins` (A right, B wrong), `bWins`,
`bothWrong`.  Attribute-level counts are summed into `*`.

## 6. Reconciliation

`reconcile(A, B, category, attribute, value_a, value_b)`:

1. If exactly one value is missing → tier **completeness**: prefer the tool that has a value; its
   probability is the posterior mean of its correctness rate for that attribute in the category.
2. Tier **head-to-head**: disagreements `n = aWins + bWins ≥ min_support_head_to_head` (3) →
   `p = P(θ > ½)`, `θ ~ Beta(aWins+1, bWins+1)`.
3. Tier **attribute**: `θ_A ~ Beta(c_A+1, n_A−c_A+1)` from A's attribute correctness in the category
   (likewise B), with `n ≥ min_support` (5) on both sides → `p = P(θ_A > θ_B)` (Simpson integration of
   pdf·cdf).
4. Tier **category**: the composite scores treated as rates with the category support as evidence.
5. Tier **global**: same with the overall scores.

Within each tier the category is backed off one facet at a time in the order
`case, scenario, library, implicit, pqc, language, family, subtype, assetType` until the support
condition holds.  Each dropped facet discounts the result: `relevance = 1 / (1 + 0.15·steps)`,
`p' = ½ + (p − ½)·relevance`.  Output: `pABetter = p'`, `weights = {A: p', B: 1−p'}`,
`confidence = max(p', 1−p')`, `decision = prefer-a | prefer-b | undecided` (`undecided` below
`undecided_below`, 0.6), the tier, the category actually used, the support, both tool versions and a
textual explanation.  `valueEvidence` additionally reports how often each tool reported the
contested value for that attribute in the category and how often it was right.

All thresholds live under `scoring:` in `orchestrator.yaml` and are copied into the scorecard, so a
`Scorecard` object reconciles with the parameters the run was scored with.

## Changes

**1.1** — file-level evidence (`fileLevel` occurrences, per-file non-asset mentions, artifact-file false
positives, best-candidate assignment on file-level hits); certificates matched by identity and their names
and validity times compared by content; shared OIDs no longer override a parameter conflict; `other` =
`other` and located mistyped secrets for related crypto material.  Re-scoring the stored outputs of the
five program cases gives the same ledger as 1.0 for every tool whose certificate detections name the
corpus certificate or nothing.

**1.0** — initial model.
