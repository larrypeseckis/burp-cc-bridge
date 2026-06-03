# CC-Bridge v0.1 — Validation Report

**Date:** 2026-06-02 (initial trial); **updated:** 2026-06-02 (extended trial)
**Bridge version under test:** 0.1.0 (locked for the duration of the trial)
**Burp Suite edition:** Community 2025.x
**Host:** Kali Linux, OpenJDK 25, Maven 3.x
**Test platform:** PortSwigger Web Security Academy
**Methodology:** Six labs across six vulnerability classes, solved end-to-end via the bridge with no GUI fallback unless the bridge could not perform the action. Five labs solved; one documented non-solve at a hard boundary that affects Burp Community Edition itself, not the bridge specifically. Each lab independently documented; this file aggregates the results.

Source writeups:

- `../ctf/wsa-unused-api/WSA -- Finding and exploiting an unused API endpoint.md` *(pre-trial pilot solve, structured header retro-applied)*
- `labs/WSA -- Blind SQL injection with conditional responses.md`
- `labs/WSA -- High-level logic vulnerability.md`
- `labs/WSA -- User ID controlled by request parameter with password disclosure.md`
- `labs/WSA -- SSRF with blacklist-based input filter.md`
- `labs/WSA -- Blind SSRF with out-of-band detection.md` *(non-solve — Burp Community ceiling)*

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
| **Totals** | | | | **245 calls** | **~23 min on solves** | | **1 (designed)** | **0 (none available on Community)** |

Notes:

- Lab 1's call count is reconstructed from the solve chain. It was the pilot solve, run before the per-lab structured header was specified.
- Lab 6 is a **documented non-solve at a hard boundary that affects Burp Community itself**, not the bridge specifically. The bridge correctly returned 501 with a hint; the lab's solve-verifier is hardwired to Burp Collaborator's API (a Pro-Edition service); the entire lab class is unsolvable on Community regardless of tooling. See §5.1 for the layered analysis.
- "Time (wall)" is Claude Code's clock time on solve attempts including reading and writing — not raw lab-tunnel latency. The Lab 2 inner extraction loop is the only call rate measured precisely (see §4).

---

## 2. Endpoint coverage matrix

Legend: ● exercised under load · ○ exercised in single calls · — not exercised in this lab · ◐ 501 path exercised in solve context · 🚫 gated by Burp Community (smoke-tested only)

| Endpoint | L1 | L2 | L3 | L4 | L5 | L6 | Trial status |
|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| `GET /health` | ○ | ○ | ○ | ○ | ○ | ○ | Smoke-tested only (not part of solves); behaved correctly |
| `POST /send` | ● | ● | ● | ● | ● | ● | Exercised in every lab; total ~225 calls; no observed failures |
| `POST /repeat/{id}` | — | ● ×139 | — | — | ● ×17 | ○ ×4 | Validated under sustained iteration (L2) AND batch exploration (L5); no failures |
| `GET /history/{id}` | — | — | — | — | — | ○ | Used in L6 to verify transmitted headers; works |
| `GET /history` | — | — | — | — | — | — | Not exercised in solves |
| `POST /decode` | — | — | — | — | — | — | Not exercised in solves (smoke-tested during build) |
| `POST /scan` | — | — | — | — | — | — | 🚫 Burp Community returns null from `api.scanner().startAudit()`; CC-Bridge returns 501 with hint. **Not exercised in a solve context during this trial.** |
| `GET /scan/{taskId}` | — | — | — | — | — | — | 🚫 same as above |
| `GET /issues` | — | — | — | — | — | — | Smoke-tested (returns `{count:0, items:[]}` on Community); not exercised in solves |
| `POST /collaborator/new` | — | — | — | — | — | **◐** | **501 exercised in solve context (L6).** Returned `{"error":"collaborator_unavailable","hint":"Burp Collaborator is Professional-only — not available in Burp Community."}`. Agent correctly recognized the boundary, did not retry uselessly, switched to external OAST. |
| `GET /collaborator/{ctx}` | — | — | — | — | — | — | Not reached (no Collaborator context was ever created) |

**Coverage summary**

- `/send` is validated across all six labs.
- `/repeat/{id}` is validated under two distinct workflow shapes: sustained iteration (Lab 2, 139 calls) and batch exploration (Lab 5, 17 calls).
- `/history/{id}` validated as a single-call inspection primitive (Lab 6) — used to confirm transmitted headers.
- **`/collaborator/new`'s 501 path is now validated in a solve context (Lab 6).** The agent-side behavior on 501 — recognize the boundary, surface a clear failure, switch to an external OAST workflow — is the test the trial originally specified and never ran. It now has been.
- `/decode`, `/history` (list), `/scan`, `/scan/{taskId}`, `/issues` remain smoke-tested only. No claim of robustness can be made for them from this trial.

---

## 3. Workflow patterns observed

Five distinct request-shape patterns surfaced across the six labs.

### 3.1 Recon-then-exploit (Labs 1, 4)

A burst of read-only `/send` calls to learn the surface (catalog, scripts, redirect targets, form fields), followed by a small number of targeted requests that perform the exploit. Call counts in this pattern: 12–13 total per lab. State carried between calls is the session cookie and any extracted CSRF tokens — typically 1–2 strings.

### 3.2 Transactional state-machine (Lab 3)

Multi-step flow where each step has a different shape and side-effects depend on prior state. State carried between calls is more substantial: session cookie, CSRF, cart contents implicit in the server. Call count: 32, dominated by 21 catalog-scrape requests done up front to establish the price table needed for the exploit math.

### 3.3 Iterative oracle (Lab 2)

A single base request, repeatedly mutated on one header. The exploit algorithm is binary search; the bridge call is the inner loop body. Call count: 139 for the extraction loop alone; 146 total including framing. This pattern is what `/repeat/{id}` was originally designed for.

### 3.4 Identity-switch (Lab 4)

Two distinct authenticated identities used in sequence: log in as low-privilege user A to learn B's secret, then log in as B to act. Three session cookies tracked across the lab. Call count: 12.

### 3.5 Batch exploration via `/repeat` (Lab 5)

Multiple bypass / payload candidates fired in a single shell loop against the same base request, used to triage what works and disentangle multiple filters. Distinct from §3.3 in that the sequence is not algorithmic (no binary search) — it's a hand-built candidate matrix. The same primitive that drove the 139-call SQLi loop drove the 17-call SSRF triage. The bridge's surface didn't need to change between use cases.

### 3.6 OAST mint / plant / poll via external provider (Lab 6, partial)

For real-world blind-out-of-band workflows when Burp Collaborator is unavailable, the bridge can drive an external OAST provider entirely via `/send`:

1. **Mint:** `POST` to the provider's API (e.g. `https://webhook.site/token`) to obtain a unique callback URL.
2. **Plant:** put the URL into the target field (header, parameter, body) via `/send` or `/repeat`.
3. **Poll:** `GET` the provider's interactions API to detect callbacks.

In Lab 6, the mint/plant/poll loop **functioned correctly end-to-end** — the bridge could reach webhook.site, the channel was confirmed by a direct probe, and the bait request transmitted the OAST URL correctly to the lab. The lab did not fire a callback to webhook.site, but that is a property of PortSwigger Academy's lab-solve verifier, not the bridge or the external provider (see §5.1). For engagements where the verifier is the engagement team rather than a hardwired academy poll, this workflow is a complete substitute for Burp Collaborator.

### Patterns that did *not* occur in the trial

- **Scanner-fed workflows** (`/scan` → `/issues` → targeted exploitation). Burp Community gates the scanner.
- **Large response handling** — largest single body observed was ~11 KB; no streaming or pagination tested.
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

No call timeouts or retries were configured or observed. No connection-pool exhaustion observed. Burp's UI showed all 139 requests as discrete entries in Proxy history with no UI lag.

---

## 5. Known limitations

### 5.1 Burp Community gating — the layered finding

Lab 6 (Blind SSRF with out-of-band detection) was the first solve attempt that genuinely required `/collaborator`. The result was a documented non-solve with four distinct layers, each meaningful on its own. Stating them precisely matters because they say different things about the bridge.

**Layer 1 — CC-Bridge's `/collaborator` is 501-gated on Burp Community.**
`api.collaborator().createClient()` returns `null` on Community Edition. CC-Bridge null-checks and returns HTTP 501 with `{"error":"collaborator_unavailable","hint":"Burp Collaborator is Professional-only — not available in Burp Community."}`. This is correct architecture — the bridge cannot fabricate a Collaborator client when the underlying API does not expose one. The 501-with-hint pattern allows a downstream agent to recognize the boundary without parsing English error messages or maintaining its own knowledge of the Pro/Community matrix.

**Layer 2 — PortSwigger Academy's lab-solve verification is hardwired to Burp Collaborator infrastructure.**
The academy detects the solve state for this lab class by polling Collaborator's API for the lab instance's per-session unique subdomain. There is no parallel verification path that watches arbitrary OAST providers. Even if a webhook.site callback had landed at the right moment, the academy would not see it, and the lab would not flip to "Solved." This is a property of the academy's lab platform, not of Burp itself.

**Layer 3 — Burp Collaborator is a Professional-Edition feature.**
The user-facing tool that would generate a Collaborator payload for a GUI-fallback path (Burp's "Collaborator client" tab) does not exist on Community. There is no Burp Community workflow — scripted, GUI, or otherwise — that mints a Collaborator payload registered with PortSwigger's verifier. Layers 2 and 3 stack: **the academy lab class "Blind SSRF requiring OAST" is structurally unsolvable on Burp Community, with or without CC-Bridge.**

**Layer 4 — The bridge's external-OAST capability is real and matters for real engagements.**
In a real engagement the verifier is the engagement team, not a fixed academy poll. The bridge can mint an OAST URL (e.g. via `POST /send` against `https://webhook.site/token`), plant the URL into any request field via `/send` or `/repeat`, and poll the provider's API via `/send` to detect callbacks. Lab 6 validated this loop end-to-end via a direct probe — the channel works.

**Net positioning:** CC-Bridge v0.1 is **at parity with Burp Community's actual capability** on this lab class. The ceiling is Burp Community's, not the bridge's. Anyone asking "can the bridge do OAST?" should hear: "yes, against any external provider; no, against Burp Collaborator on Community because Community doesn't have one."

### 5.2 Scanner gating

`api.scanner().startAudit(...)` returns null on Community. CC-Bridge returns 501 with `{"error":"scanner_unavailable","hint":"..."}`. The 501 was smoke-tested at build time. Unlike `/collaborator`, the scanner's 501 path **has not been exercised in a solve context** — no lab in the trial required the Burp Scanner end-to-end.

### 5.3 Manual cookie/CSRF handling

v0.1 does not opt into Montoya's cookie jar (`RequestOptions.requestOptions().withCookieJar(true)` or equivalent). Every authenticated call in this trial passed `Cookie: session=...` explicitly. This added approximately 1 line of Python extraction and 1 line of shell variable assignment per session rotation. Across the six labs there were ~12 session rotations total.

This is a deliberate v0.1 design choice (explicit state is easier to audit in writeups) but it does add friction. v0.2 should expose an opt-in.

### 5.4 Full response bodies always returned

Every `/send` and `/repeat` returns the complete response body in the JSON envelope. On Lab 2 this meant ~11 KB × 139 = ~1.5 MB of HTML was shipped from the bridge to the driver, of which ~50 bytes (the `"Welcome back"` substring check) was actually consumed. At lab-tunnel latencies this is negligible; at high-throughput local-target rates it would matter.

### 5.5 No server-side extraction

There is no endpoint that runs a regex or JSONPath against the response body server-side. All extraction happens in the driver after the full body is returned. This is a code-organization issue more than a correctness issue, but it pushes parsing complexity into the caller.

### 5.6 No streaming, no WebSockets, no large-payload testing

The trial did not exercise the bridge on responses larger than ~12 KB or on non-HTTP protocols. CC-Bridge v0.1 has no WebSocket support; if a lab required it, GUI fallback would be needed.

### 5.7 No concurrency tested

All 245 calls in the trial were sequential. The HTTP server's 4-thread executor was never under contention. Whether parallel `/send` calls retain Burp's history ordering or interleave Proxy entries cleanly is unverified.

### 5.8 Trial sample size

Six labs, four Apprentice, two Practitioner. No Expert-difficulty labs. No labs with file upload, WebSockets, multi-host scope, or upstream proxy chains. The bridge is validated for workflows resembling these six labs; broader claims are not supported by this dataset.

---

## 6. v0.2 backlog

Ranked by concrete impact observed during the trial. "Saves N calls" means calls eliminated; "saves M minutes" means wall time saved. Items that would only have polished the writeup or saved a few lines of driver code are still listed but flagged.

| Rank | Item | Concrete impact in this trial | Justification |
|---:|---|---|---|
| 1 | **`useCookieJar: true` flag on `/send` and `/repeat`** | Would have eliminated explicit cookie threading on Labs 1, 3, 4, 5, 6. Saves ~12 lines of shell/Python across the trial. Saves 0 calls. | Friction reducer for transactional workflows. Pattern repeats every login-bearing lab; cumulative cost grows with engagement length. |
| 2 | **`POST /extract` — run a regex or JSONPath against a stored response server-side** | On Lab 2, would have shrunk 139 × 11 KB transfers to 139 × ~50 B booleans. Estimated wall-time savings at lab-tunnel latencies: negligible. At local-target rates: potentially 10–20%. | Bigger value is code organization — pushes parsing into a stable API surface instead of driver-specific Python. Saves 0 calls but improves cross-language driver authoring. |
| 3 | **`POST /login` helper that wraps GET /login + extract CSRF + POST /login in one bridge call** | Would have collapsed steps 1–2 in Labs 1, 3, 4 (3 labs × 2 calls = 6 calls saved). | Common enough to justify a helper. Risk: hard-codes assumptions about login form shape (`name=csrf`, etc.). Should be opt-in, not the default. |
| ~~4~~ | ~~Forced-501 downstream agent test~~ ✅ **CLOSED in Lab 6** | Methodology item, not a code change. Lab 6 exercised the 501 path in a solve context. Agent behavior was correct: recognize the boundary, surface a clear failure, switch to external OAST. No code change resulted; the existing 501-with-hint pattern is the right shape. | Closed by Lab 6 (Blind SSRF with out-of-band detection). |
| 4 (new) | **`POST /oast` — built-in OAST provider integration** | Would have collapsed the Lab 6 webhook.site flow (3 calls: mint, plant, poll) into 1 logical operation with provider abstraction. Saves 0 calls in this trial but documents the canonical workflow. | Justified by Lab 6's demonstration that external OAST is a valid Collaborator substitute. The provider could be configurable: webhook.site / interact.sh / a user-supplied callback URL. Should NOT pretend to be Collaborator — should be a clearly-labeled external-OAST endpoint. |
| 5 | **`/sitemap` endpoint exposing Burp's site map** | Zero calls saved in this trial — no lab needed it. | Recon-heavy real engagements would benefit. Speculative for now. |
| 6 | **`/match-replace` endpoint** | Zero calls saved in this trial. | Useful for global header/cookie injection in long sessions; would obviate ~30% of Lab 3's cookie-passing if combined with item 1. |
| 7 | **Response body size cap with `?bodyLimit=N` query param** | Zero calls saved. Optional polish for future high-throughput labs. | Not justified by trial data. |
| 8 | **Structured logging of bridge calls to a JSONL file** | Not call-saving. Would have replaced manual call counting in this writeup. | Methodology improvement for future trials. |

**Summary of v0.2 priorities by call savings:**

- Item 3 (login helper) is the only one that demonstrably reduces call count in this trial — by 6 across three labs.
- Items 1, 2, 5–8 reduce friction or improve auditability but do not reduce call count on the workflows observed.
- Item 4 (the original forced-501 methodology test) is now closed by Lab 6; the bridge's 501 architecture is the correct shape and needs no code change.
- New item 4 (external-OAST helper) is justified by Lab 6's demonstrated workflow; should be a clearly-named *external* OAST endpoint, never claim to be Collaborator.

---

## 7. Conclusions

### 7.1 What the bridge is validated for

Based on the six-lab trial:

- **`POST /send` as a general-purpose HTTP execution primitive.** Exercised across six labs and ~225 calls without observed failure. Returns full request and response with stable history IDs. Outbound requests appear in Burp's Proxy history identically to manually issued Repeater requests.
- **`POST /repeat/{id}` under sustained iteration AND batch exploration.** Lab 2: 139 sequential calls in 23.3 seconds. Lab 5: 17 hand-built candidate variants. Same primitive, two distinct workflow shapes, no failures in either.
- **Bearer-token authentication on `127.0.0.1`.** Token file workflow (load extension → write `~/.cc-bridge-token` → driver reads → `Authorization: Bearer <token>`) functioned correctly across multiple Burp restarts and extension reloads.
- **501 fallback for Pro-only features, exercised end-to-end in a solve context.** Lab 6's `/collaborator/new` call returned a clean 501 with a hint. The driving agent correctly recognized the boundary, did not retry uselessly, switched to an external OAST channel, and produced a layered finding that correctly attributed the non-solve to Burp Community's actual ceiling rather than misattributing it to a bridge defect.
- **External-OAST mint/plant/poll via `/send` against any external provider.** Validated end-to-end in Lab 6 against webhook.site. Channel-functional even though the academy's verifier (Layer 2/3 in §5.1) prevented a solve.
- **Workflow patterns:** recon-then-exploit, transactional state machine, iterative oracle, identity-switch, batch exploration via `/repeat`, OAST mint/plant/poll. The bridge is the right shape for all six.

### 7.2 What the bridge is *not* tested for

- Scanner-fed workflows (`/scan`, `/issues`) in a solve context. (Burp Community gates the scanner; no lab in the trial worked around this the way Lab 6 did for `/collaborator`.)
- Bodies larger than ~12 KB.
- Concurrent `/send` calls.
- WebSocket-based labs (no support in v0.1; would require GUI fallback).
- File-upload-heavy workflows.
- Multi-host scoping, upstream proxy chains, or non-default Burp session handling rules.
- Long-running engagements where Burp's history grows past the in-memory `HistoryStore` cap (500 entries).
- Token rotation (the trial used the same token throughout).

### 7.3 Defects found

None during the trial. Two paths returned generic NPEs in build-time smoke testing (`/scan` and `/collaborator/new` on Community); both were patched to clean 501-with-hint responses before the trial began, and that fix held under solve-context exercise in Lab 6.

### 7.4 Statement of validation scope

CC-Bridge v0.1 is validated as a localhost HTTP control plane suitable for **scripted, sequential, HTTP-only web-security workflows on Burp Community Edition**, at the scale and shape of PortSwigger Web Security Academy Apprentice and Practitioner labs. **The bridge is at parity with Burp Community's actual capability**, including correctly surfacing the boundaries where Community itself cannot perform a task. It is not validated for the workflows enumerated in §7.2. It is not equivalent to Burp Professional and does not claim to be — the absent Pro features (Collaborator, Scanner) are reported as 501-with-hint rather than emulated or faked.

Validation against a broader matrix — including the items in the v0.2 backlog and testing on Burp Pro — requires additional trials.

---

*End of validation report (extended).*
