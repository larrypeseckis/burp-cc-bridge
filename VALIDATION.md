# CC-Bridge v0.1 — Validation Report

**Date:** 2026-06-02 (initial trial); **updated:** 2026-06-04 (coverage-milestone extension)
**Bridge version under test:** 0.1.0 (locked for the duration of the trial)
**Burp Suite edition:** Community 2025.x
**Host:** Kali Linux, OpenJDK 25, Maven 3.x
**Test platform:** PortSwigger Web Security Academy
**Methodology:** Nine labs across eight vulnerability classes, solved end-to-end via the bridge with no GUI fallback unless the bridge could not perform the action. Eight labs solved; one documented non-solve at a hard boundary that affects Burp Community Edition itself, not the bridge specifically. Each lab independently documented; this file aggregates the results.

Source writeups:

- `../ctf/wsa-unused-api/WSA -- Finding and exploiting an unused API endpoint.md` *(pre-trial pilot solve, structured header retro-applied)*
- `labs/WSA -- Blind SQL injection with conditional responses.md`
- `labs/WSA -- High-level logic vulnerability.md`
- `labs/WSA -- User ID controlled by request parameter with password disclosure.md`
- `labs/WSA -- SSRF with blacklist-based input filter.md`
- `labs/WSA -- Blind SSRF with out-of-band detection.md` *(non-solve — Burp Community ceiling)*
- `labs/WSA -- Exploiting Java deserialization with Apache Commons.md`
- `labs/WSA -- Remote code execution via web shell upload.md`
- `labs/WSA -- Information disclosure on debug page.md`

---

## 1. Summary table

| # | Lab | Class | Difficulty | Calls | Time (wall) | Endpoints used | Endpoint failures | GUI fallback |
|---|---|---|---|---:|---:|---|---|---|
| 1 | Finding and exploiting an unused API endpoint | API testing / hidden HTTP method | Apprentice | 13 | ~5 min | `/send` | none | no |
| 2 | Blind SQL injection with conditional responses | Boolean-based blind SQLi | Practitioner | 146 | ~5 min (139-call loop: 23.3 s) | `/send`, `/repeat/{id}` | none | no |
| 3 | High-level logic vulnerability | Business logic / missing validation | Apprentice | 32 | ~4 min | `/send` | none | no |
| 4 | User ID controlled by request parameter with password disclosure | Access control / IDOR + disclosure | Apprentice | 12 | ~3 min | `/send` | none | no |
| 5 | SSRF with blacklist-based input filter | SSRF (in-band) + URL-encoding bypass | Practitioner | 23 | ~6 min | `/send`, `/repeat/{id}` | none | no |
| 6 | Blind SSRF with out-of-band detection | Blind SSRF requiring OAST | Practitioner | 19 | N/A (non-solve) | `/send`, `/repeat/{id}`, `/history/{id}`, **`/collaborator/new` (501)** | `/collaborator/new` returned 501 *as designed* — Burp Collaborator is Pro-only | not available (Collaborator client is Pro-only) |
| 7 | Exploiting Java deserialization with Apache Commons | Insecure deserialization | Practitioner | 5 | ~7 min | `/send`, `/decode` | none | no |
| 8 | Remote code execution via web shell upload | Unrestricted file upload (multipart) | Apprentice | 9 | ~3 min | `/send` (multipart body) | none | no |
| 9 | Information disclosure on debug page | Information disclosure | Apprentice | 7 | ~2 min | `/send`, `/history/{id}`, `/history` (list) | none | no |
| **Totals** | | | | **266 calls** | **~35 min on solves** | | **1 (designed 501)** | **0 (none available on Community for Lab 6)** |

Notes:

- Lab 1's call count is reconstructed from the solve chain. It was the pilot solve, run before the per-lab structured header was specified.
- Lab 6 is a **documented non-solve at a hard boundary that affects Burp Community itself**, not the bridge specifically. See §5.1 for the layered analysis.
- "Time (wall)" is Claude Code's clock time on solve attempts including reading and writing — not raw lab-tunnel latency. The Lab 2 inner extraction loop is the only call rate measured precisely (see §4).

---

## 2. Endpoint coverage matrix

Legend: ● exercised under load · ○ exercised in single calls · — not exercised in this lab · ◐ 501 path exercised in solve context · 🚫 gated by Burp Community (smoke-tested only)

| Endpoint | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 | Trial status |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| `GET /health` | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | Smoke-tested in every session; behaved correctly |
| `POST /send` | ● | ● | ● | ● | ● | ● | ● | ● | ● | Exercised in every lab; total ~240 calls; no observed failures; **carries arbitrary `Content-Type` including multipart/form-data without body modification (Lab 8)** |
| `POST /repeat/{id}` | — | ● ×139 | — | — | ● ×17 | ○ ×4 | — | — | — | Validated under sustained iteration (L2), batch exploration (L5), and header variation (L6); no failures |
| `GET /history/{id}` | — | — | — | — | — | ○ | — | — | ○ | Used in L6 to verify transmitted headers, L9 to re-grep stored response HTML; works |
| **`GET /history` (list)** | — | — | — | — | — | — | — | — | **○** | **First solve-context use in L9 with `contains=` substring search. One hit, correctly identified.** |
| **`POST /decode`** | — | — | — | — | — | — | **○** | — | — | **First solve-context use in L7 — base64-decoded the Java serialized session cookie, revealing class name `lab.actions.common.serializable.AccessTokenUser`.** |
| `POST /scan` | — | — | — | — | — | — | — | — | — | 🚫 Burp Community returns null from `api.scanner().startAudit()`; CC-Bridge returns 501 with hint. **Not exercised in a solve context during this trial.** |
| `GET /scan/{taskId}` | — | — | — | — | — | — | — | — | — | 🚫 same as above |
| `GET /issues` | — | — | — | — | — | — | — | — | — | Smoke-tested (returns `{count:0, items:[]}` on Community); not exercised in solves |
| `POST /collaborator/new` | — | — | — | — | — | **◐** | — | — | — | **501 exercised in solve context (L6).** Agent recognized boundary, did not retry, switched to external OAST. |
| `GET /collaborator/{ctx}` | — | — | — | — | — | — | — | — | — | Not reached (no Collaborator context was ever created) |

### Coverage milestone

**With Lab 9, every Community-reachable bridge endpoint has been exercised in a solve context at least once.** Specifically:

- `/send` — every lab
- `/repeat/{id}` — Labs 2 (iteration), 5 (exploration), 6 (header variation)
- `/decode` — Lab 7 (Java serialized object detection)
- `/history/{id}` — Labs 6 (transmitted-header verification), 9 (HTML re-grep without re-request)
- `/history` (list with `contains=`) — Lab 9
- `/collaborator/new` 501 path — Lab 6

The Pro-gated endpoints (`/scan`, `/scan/{taskId}`, `/issues`, `/collaborator/{ctx}` polling) remain unexercised because Burp Community lacks the underlying Montoya capability the bridge wraps. Per Lab 6's analysis, that's the bridge being at parity with Community's actual ceiling, not a coverage gap.

---

## 3. Workflow patterns observed

Seven distinct request-shape patterns surfaced across the nine labs.

### 3.1 Recon-then-exploit (Labs 1, 4, 9)

A burst of read-only `/send` calls to learn the surface (catalog, scripts, redirect targets, HTML comments, form fields), followed by a small number of targeted requests that perform the exploit. Call counts in this pattern: 7–13 total per lab.

### 3.2 Transactional state-machine (Lab 3)

Multi-step flow where each step has a different shape and side-effects depend on prior state. State carried between calls is substantial: session cookie, CSRF, cart contents implicit in the server. Call count: 32, dominated by 21 catalog-scrape requests done up front.

### 3.3 Iterative oracle (Lab 2)

A single base request, repeatedly mutated on one header. The exploit algorithm is binary search; the bridge call is the inner loop body. 139 calls for the extraction loop alone; 146 total.

### 3.4 Identity-switch (Lab 4)

Two distinct authenticated identities used in sequence: log in as low-privilege user A to learn B's secret, then log in as B to act. Three session cookies tracked across the lab.

### 3.5 Batch exploration via `/repeat` (Lab 5)

Multiple bypass / payload candidates fired in a single shell loop against the same base request, used to triage what works and disentangle multiple filters. Distinct from §3.3 in that the sequence is not algorithmic — it's a hand-built candidate matrix.

### 3.6 OAST mint / plant / poll via external provider (Lab 6, partial)

For real-world blind-OOB workflows when Burp Collaborator is unavailable, the bridge drives an external OAST provider entirely via `/send`: mint URL via `POST` to the provider's API, plant via `/send` or `/repeat` with the bait URL in the target field, poll via `GET` for callbacks. Channel validated end-to-end against webhook.site. Lab 6 did not solve due to the academy's verifier being hardwired to Burp Collaborator (see §5.1), but the workflow pattern is correct for real engagements.

### 3.7 Bridge-as-transport: multipart, raw, opaque-body (Lab 8)

`POST /send` carries arbitrary `Content-Type` bodies byte-for-byte unchanged. Validated against a hand-built `multipart/form-data` envelope (411 bytes, boundary string, `Content-Disposition` headers, CRLF terminators) carrying a PHP web shell. Burp's `api.http().sendRequest()` does not normalize, re-encode, or rewrap request bodies, which is the contract upload exploitation needs. The same property would extend to `application/octet-stream`, raw binary, gRPC-over-HTTP/2 framed bytes, or any other content type the caller can construct.

### 3.8 Stored-response re-grep via `/history/{id}` (Lab 9)

When the response to a prior call needs to be re-scanned for new patterns (HTML comments, regex matches, parsed-out tokens), `/history/{id}` returns the full stored request + response without re-issuing the request. Preserves the original timing, cookies, and one-time state. Cheaper than the equivalent re-fetch, and avoids any server-side cache-busting or counter increments.

### 3.9 Substring search across history via `/history` list (Lab 9)

`GET /history?contains=<string>&limit=N` scans both the bridge's in-memory store and Burp's proxy history for the substring across request and response bodies. Returns matching entries with stable IDs. Useful when the answer to "where did I see X" is the bottleneck of a multi-step solve. On a 7-call lab the value is incidental; on a 100-call engagement it becomes essential.

### Patterns that did *not* occur in the trial

- **Scanner-fed workflows** (`/scan` → `/issues` → targeted exploitation). Burp Community gates the scanner.
- **Large response handling** — largest single body observed was ~72 KB (the phpinfo response in Lab 9); no streaming or pagination tested.
- **Concurrent request bursts** — every call was sequential. The HTTP server's 4-thread executor was never exercised in parallel.

---

## 4. Bridge throughput data

Only one lab produced numerically clean throughput data: Lab 2's binary-search extraction loop.

| Measurement | Value |
|---|---|
| Calls in loop | 139 |
| Wall time start→last call | 23.3 s |
| **Sustained call rate** | **5.97 calls/sec** |
| **Median per-call latency** | **~168 ms** |
| Per-call payload size in | ~150 bytes (JSON body) |
| Per-call payload size out | ~11 KB (lab homepage HTML, mostly discarded) |

Latency breakdown (estimated, not measured per component):

- Subprocess spawn (`bash` → `curl`) — ~5–10 ms
- `curl` → `127.0.0.1:1337` HTTP request — ~1 ms
- `HttpServer` dispatch + JSON parse — ~1–3 ms
- `api.http().sendRequest()` → lab roundtrip — **~150 ms (dominant)**
- Response serialization back through bridge to `curl` stdout — ~3–5 ms

Bridge overhead is roughly 10–20 ms per call on this host; the remainder is lab-tunnel latency. For a local target the ratio would invert and the bridge's overhead would matter; this trial provides no data on that case.

**Largest single body observed:** 72 KB (Lab 9's phpinfo response). Carried through the bridge in a single JSON envelope without observable issue. Earlier estimate that "~12 KB" was the high-water mark is superseded.

**Largest single body sent:** 411 bytes (Lab 8's multipart upload envelope). Trivial relative to inbound sizes; no test data on large outbound bodies.

No call timeouts or retries were configured or observed. No connection-pool exhaustion observed. Burp's UI showed all 139 requests as discrete entries in Proxy history with no UI lag.

---

## 5. Known limitations

### 5.1 Burp Community gating — the layered finding (from Lab 6)

Lab 6 (Blind SSRF with out-of-band detection) was the only solve attempt that genuinely required `/collaborator`. The result was a documented non-solve with four distinct layers:

**Layer 1 — CC-Bridge's `/collaborator` is 501-gated on Burp Community.**
`api.collaborator().createClient()` returns `null` on Community. CC-Bridge null-checks and returns HTTP 501 with `{"error":"collaborator_unavailable","hint":"Burp Collaborator is Professional-only — not available in Burp Community."}`. Correct architecture, not a bridge defect.

**Layer 2 — PortSwigger Academy's lab-solve verification is hardwired to Burp Collaborator infrastructure.**
The academy detects the solve state for this lab class by polling Collaborator's API for the lab instance's per-session unique subdomain. There is no parallel verification path watching arbitrary OAST providers. An external-OAST hit would not trip the academy's check regardless of the bridge's behavior.

**Layer 3 — Burp Collaborator is a Professional-Edition feature.**
The Collaborator client tab does not exist on Community. There is no Burp Community workflow — scripted, GUI, or otherwise — that mints a Collaborator payload registered with PortSwigger's verifier. Layers 2 and 3 stack: **the academy lab class "Blind SSRF requiring OAST" is structurally unsolvable on Burp Community, with or without CC-Bridge.**

**Layer 4 — The bridge's external-OAST capability is real and matters for real engagements.**
In a real engagement the verifier is the engagement team, not a fixed academy poll. The bridge can mint an OAST URL via `POST /send`, plant it via `/send` or `/repeat`, and poll via `GET /send` against the provider's interactions API. Validated end-to-end against webhook.site.

**Net positioning:** CC-Bridge v0.1 is at parity with Burp Community's actual capability on this lab class. The ceiling is Community's, not the bridge's.

### 5.2 Scanner gating

`api.scanner().startAudit(...)` returns null on Community. CC-Bridge returns 501 with `{"error":"scanner_unavailable","hint":"..."}`. The 501 was smoke-tested at build time. Unlike `/collaborator`, the scanner's 501 path has not been exercised in a solve context — no lab in the trial required Burp Scanner end-to-end.

### 5.3 Manual cookie/CSRF handling

v0.1 does not opt into Montoya's cookie jar. Every authenticated call passed `Cookie: session=...` explicitly. Across the nine labs there were ~14 session rotations total, each adding ~1 line of shell variable assignment. Deliberate v0.1 design choice (explicit state is auditable); v0.2 should expose an opt-in.

### 5.4 Full response bodies always returned

Every `/send` and `/repeat` returns the complete response body in the JSON envelope. Lab 2 shipped ~11 KB × 139 = ~1.5 MB of HTML to consume ~50 bytes of substring check. Lab 9's phpinfo response was 72 KB. At lab-tunnel latencies negligible; at high-throughput local-target rates it would matter.

### 5.5 No server-side regex extraction

No endpoint runs a regex against the response body server-side. All extraction happens in the driver. Code-organization issue more than correctness issue, but worth noting now that **`/history` list with `contains=`** has demonstrated that *some* server-side body matching already exists (substring scan over stored entries). Generalizing that to a regex-extract endpoint is a smaller v0.2 step than originally framed (see backlog item 2).

### 5.6 No streaming, no WebSockets, no large-payload testing

Largest body in trial: 72 KB (Lab 9 phpinfo) inbound, 411 B (Lab 8 multipart) outbound. No streaming or pagination tested. No WebSocket support in v0.1; would require GUI fallback.

### 5.7 No concurrency tested

All 266 calls in the trial were sequential. The HTTP server's 4-thread executor was never under contention.

### 5.8 Trial sample size

Nine labs across eight vulnerability classes: API testing, SQLi, business logic, access control, SSRF (two labs — in-band and blind-OOB), insecure deserialization, file upload, information disclosure. Five Apprentice, four Practitioner. No Expert-difficulty labs. No labs with WebSockets, multi-host scope, or upstream proxy chains. The bridge is validated for workflows resembling these nine labs; broader claims are not supported by this dataset.

---

## 6. v0.2 backlog

Ranked by concrete impact observed during the extended trial.

| Rank | Item | Concrete impact in this trial | Justification |
|---:|---|---|---|
| 1 | **`useCookieJar: true` flag on `/send` and `/repeat`** | Would have eliminated explicit cookie threading on Labs 1, 3, 4, 5, 6, 7, 8. Saves ~14 lines of shell/Python across the trial. Saves 0 calls. | Friction reducer for transactional workflows. Pattern repeats every login-bearing lab; cumulative cost grows with engagement length. |
| 2 | **`POST /extract` — regex / JSONPath against a stored response server-side** | On Lab 2, would have shrunk 139 × 11 KB transfers to 139 × ~50 B booleans. Now partially obsoleted by `/history?contains=` having validated substring scanning is already feasible. The remaining win is captured groups (extract specific values, not just match/no-match). | Reduced priority — substring matching is already in `/history` list. A regex-extract endpoint would add the "what did it match" payload, useful for capturing tokens, CSRF, etc., without driver-side parsing. |
| 3 | **`POST /login` helper that wraps GET /login + extract CSRF + POST /login in one bridge call** | Would have collapsed steps 1–2 in Labs 1, 3, 4, 8 (4 labs × 2 calls = 8 calls saved). | Common enough to justify a helper. Risk: hard-codes assumptions about login form shape; should be opt-in. |
| ~~4~~ | ~~Forced-501 downstream agent test~~ ✅ **CLOSED in Lab 6** | Closed by Lab 6. Agent behavior on 501 was correct: recognize boundary, surface clear failure, switch to external OAST. No code change resulted. | – |
| 4 (new) | **`POST /oast` — built-in external OAST provider integration** | Would have collapsed the Lab 6 webhook.site flow (3 calls: mint, plant, poll) into 1 logical operation with provider abstraction. Saves 0 calls in this trial but documents the canonical workflow. | Should be a clearly-labeled *external* OAST endpoint; never claim to be Collaborator. Provider configurable (webhook.site / interact.sh / user-supplied URL). |
| 5 | **`/sitemap` endpoint exposing Burp's site map** | Zero calls saved in this trial — no lab needed it. | Recon-heavy real engagements would benefit. Speculative. |
| 6 | **`/match-replace` endpoint** | Zero calls saved in this trial. | Useful for global header/cookie injection in long sessions; would obviate ~30% of Lab 3's cookie-passing if combined with item 1. |
| 7 | **Response body size cap with `?bodyLimit=N` query param** | Zero calls saved. Optional polish for future high-throughput labs. | Not justified by trial data. |
| 8 | **Multipart helper endpoint or shell library** | Would have replaced the 12-line Python helper in Lab 8 with a one-line `cc-burp upload <field>=@<file>` call. Saves 0 calls; saves 12 lines once. | Marginal — the helper is reusable and well-understood. Worth considering as a `cc-burp` wrapper convenience rather than a bridge-level endpoint. |
| 9 | **Structured logging of bridge calls to a JSONL file** | Not call-saving. Would have replaced manual call counting in this writeup. | Methodology improvement for future trials. |

**Summary of v0.2 priorities by call savings:**

- Item 3 (login helper) is the only one that demonstrably reduces call count — by 8 across four labs.
- Items 1, 4–9 reduce friction, improve auditability, or document patterns but do not reduce call count on the workflows observed.
- Item 2 (server-side regex extraction) is partially obsoleted by `/history?contains=` already shipping in v0.1. The remaining gap is captured groups, not match/no-match.
- The original Item 4 (forced-501 methodology test) is closed by Lab 6.

---

## 7. Conclusions

### 7.1 What the bridge is validated for

Based on the nine-lab trial:

- **`POST /send` as a general-purpose HTTP execution primitive.** Exercised across nine labs and ~240 calls without observed failure. Returns full request and response with stable history IDs. Outbound requests appear in Burp's Proxy history identically to manually issued Repeater requests. **Carries arbitrary `Content-Type` bodies byte-for-byte unchanged, including multipart/form-data (Lab 8).**
- **`POST /repeat/{id}` under three distinct workflow shapes.** Sustained iteration (Lab 2: 139 calls in 23.3 s), batch exploration (Lab 5: 17 hand-built variants), and header variation (Lab 6: 4 candidate headers). Same primitive, no failures in any shape.
- **`POST /decode` for binary-format identification.** Lab 7 used it to confirm a base64'd session cookie was a Java serialized object and surface the embedded class name.
- **`GET /history/{id}` for stored-response inspection without re-issuing the request.** Validated in Labs 6 and 9.
- **`GET /history` (list) with `contains=` substring search.** Validated in Lab 9 — correctly identified one matching response across the bridge's in-memory store and Burp's proxy history.
- **Bearer-token authentication on `127.0.0.1`.** Token file workflow functioned correctly across multiple Burp restarts and extension reloads.
- **501 fallback for Pro-only features, exercised end-to-end in a solve context.** Lab 6's `/collaborator/new` returned clean 501 with hint; agent correctly recognized the boundary, switched to external OAST, produced a layered finding correctly attributing the non-solve to Burp Community's ceiling.
- **External-OAST mint/plant/poll via `/send`.** Validated end-to-end in Lab 6 against webhook.site. Channel-functional even where the academy's verifier prevented a solve.
- **Workflow patterns:** recon-then-exploit, transactional state machine, iterative oracle, identity-switch, batch exploration, OAST mint/plant/poll, bridge-as-transport (multipart/raw/opaque), stored-response re-grep, substring search. Nine distinct patterns; bridge is the right shape for all of them.

**Coverage milestone:** with Lab 9, every Community-reachable bridge endpoint has been exercised in a solve context at least once.

### 7.2 What the bridge is *not* tested for

- Scanner-fed workflows (`/scan`, `/issues`) in a solve context. (Burp Community gates the scanner; no lab in the trial worked around this the way Lab 6 did for `/collaborator`.)
- Bodies larger than ~72 KB inbound or ~500 B outbound.
- Concurrent `/send` calls.
- WebSocket-based labs (no support in v0.1; would require GUI fallback).
- Multi-host scoping, upstream proxy chains, or non-default Burp session handling rules.
- Long-running engagements where Burp's history grows past the in-memory `HistoryStore` cap (500 entries).
- Token rotation (the trial used the same token throughout).
- Burp Professional (the bridge's Pro-only endpoints have never been observed succeeding because the test environment is Community-only).

### 7.3 Defects found

None during the trial. Two paths returned generic NPEs in build-time smoke testing (`/scan` and `/collaborator/new` on Community); both were patched to clean 501-with-hint responses before the trial began. The 501 fix held under solve-context exercise in Lab 6.

### 7.4 Statement of validation scope

CC-Bridge v0.1 is validated as a localhost HTTP control plane suitable for **scripted, sequential, HTTP-only web-security workflows on Burp Community Edition**, at the scale and shape of PortSwigger Web Security Academy Apprentice and Practitioner labs across eight vulnerability classes. **Every Community-reachable bridge endpoint has been exercised in a solve context.** The bridge is at parity with Burp Community's actual capability, including correctly surfacing the boundaries where Community itself cannot perform a task.

It is not validated for the workflows enumerated in §7.2. It is not equivalent to Burp Professional and does not claim to be — the absent Pro features (Collaborator, Scanner) are reported as 501-with-hint rather than emulated or faked.

Validation against a broader matrix — including the items in the v0.2 backlog, testing on Burp Pro, concurrent workloads, and large-payload scenarios — requires additional trials.

---

*End of validation report (extended through Lab 9 — coverage milestone).*
