# CC-Bridge v0.1 — Validation Report

**Date:** 2026-06-02
**Bridge version under test:** 0.1.0 (locked for the duration of the trial)
**Burp Suite edition:** Community 2025.x
**Host:** Kali Linux, OpenJDK 25, Maven 3.x
**Test platform:** PortSwigger Web Security Academy
**Methodology:** Four labs across four vulnerability classes, solved end-to-end with no GUI fallback unless the bridge could not perform the action. Each lab independently documented; this file aggregates the results.

Source writeups (in `labs/`):

- `WSA -- Finding and exploiting an unused API endpoint.md` *(in `../ctf/wsa-unused-api/`; pre-trial pilot solve, structured header retro-applied below)*
- `WSA -- Blind SQL injection with conditional responses.md`
- `WSA -- High-level logic vulnerability.md`
- `WSA -- User ID controlled by request parameter with password disclosure.md`

---

## 1. Summary table

| # | Lab | Class | Difficulty | Calls | Time (wall) | Endpoints used | Endpoint failures | GUI fallback |
|---|---|---|---|---:|---:|---|---|---|
| 1 | Finding and exploiting an unused API endpoint | API testing / hidden HTTP method | Apprentice | 13 | ~5 min | `/send` | none | no |
| 2 | Blind SQL injection with conditional responses | Boolean-based blind SQLi | Practitioner | 146 | ~5 min (139-call loop: 23.3 s) | `/send`, `/repeat/{id}` | none | no |
| 3 | High-level logic vulnerability | Business logic / missing validation | Apprentice | 32 | ~4 min | `/send` | none | no |
| 4 | User ID controlled by request parameter with password disclosure | Access control / IDOR + disclosure | Apprentice | 12 | ~3 min | `/send` | none | no |
| **Totals** | | | | **203 calls** | **~17 min** | | **0 failures** | **0 fallbacks** |

Notes:

- Lab 1's call count is reconstructed from the solve chain. It was the pilot solve, run before the per-lab structured header was specified.
- "Time (wall)" is Claude Code's clock time including reading and writing — not raw lab-tunnel latency. The Lab 2 inner extraction loop is the only call rate measured precisely (see §4).
- The trial did not include a lab that requires `/scan` or `/collaborator` end-to-end (see §5).

---

## 2. Endpoint coverage matrix

Legend: ● exercised under load · ○ exercised in single calls · — not exercised · 🚫 gated by Burp Community

| Endpoint | Lab 1 | Lab 2 | Lab 3 | Lab 4 | Trial status |
|---|:--:|:--:|:--:|:--:|---|
| `GET /health` | ○ | ○ | ○ | ○ | Smoke-tested only (not part of solves); behaved correctly |
| `POST /send` | ● | ● | ● | ● | Exercised in every lab; total ~203 calls; no observed failures |
| `POST /repeat/{id}` | — | ● ×139 | — | — | Exercised under sustained load on Lab 2; no observed failures |
| `GET /history/{id}` | — | — | — | — | Not needed (each `/send` returns full response inline) |
| `GET /history` | — | — | — | — | Not exercised in solves |
| `POST /decode` | — | — | — | — | Not exercised in solves (smoke-tested during build) |
| `POST /scan` | — | — | — | — | 🚫 Burp Community returns null from `api.scanner().startAudit()`; CC-Bridge returns 501 with hint. **Not exercised in a solve context during this trial.** |
| `GET /scan/{taskId}` | — | — | — | — | 🚫 same as above |
| `GET /issues` | — | — | — | — | Smoke-tested (returns `{count:0, items:[]}` on Community); not exercised in solves |
| `POST /collaborator/new` | — | — | — | — | 🚫 Burp Community returns null from `api.collaborator().createClient()`; CC-Bridge returns 501 with hint. **Not exercised in a solve context during this trial.** |
| `GET /collaborator/{ctx}` | — | — | — | — | 🚫 same as above |

**Coverage summary**

- `/send` is the only endpoint validated across all four labs.
- `/repeat/{id}` is validated under sustained iteration on one lab.
- `/decode`, `/history`, `/history/{id}` were smoke-tested at build time but not used in any solve. No claim of robustness can be made for them from this trial.
- The 501 paths for `/scan` and `/collaborator` were verified to return a clean 501 with a hint message during build-time smoke testing, but no solve attempt actually depended on either of them. The "forced 501 fallback" lab category was specified in the trial plan but was not run.

---

## 3. Workflow patterns observed

Four distinct request-shape patterns surfaced across the four labs.

### 3.1 Recon-then-exploit (Labs 1, 4)

A burst of read-only `/send` calls to learn the surface (catalog, scripts, redirect targets, form fields), followed by a small number of targeted requests that perform the exploit. Call counts in this pattern: 12–13 total per lab. State carried between calls is the session cookie and any extracted CSRF tokens — typically 1–2 strings.

### 3.2 Transactional state-machine (Lab 3)

Multi-step flow where each step has a different shape and side-effects depend on prior state. State carried between calls is more substantial: session cookie, CSRF, cart contents implicit in the server. Call count: 32, dominated by 21 catalog-scrape requests done up front to establish the price table needed for the exploit math.

### 3.3 Iterative oracle (Lab 2)

A single base request, repeatedly mutated on one header. The exploit algorithm is binary search; the bridge call is the inner loop body. Call count: 139 for the extraction loop alone; 146 total including framing. This pattern is what `/repeat/{id}` exists for, and is the only one in the trial that exercised it.

### 3.4 Identity-switch (Lab 4)

Two distinct authenticated identities used in sequence: log in as low-privilege user A to learn B's secret, then log in as B to act. Three session cookies tracked across the lab. Call count: 12.

### Patterns that did *not* occur in the trial

- **Out-of-band callback driven workflows** (would have required `/collaborator`).
- **Scanner-fed workflows** (`/scan` → `/issues` → targeted exploitation).
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

### 5.1 Burp Community gating

`api.scanner().startAudit(...)` and `api.collaborator().createClient()` both return `null` on Burp Community. CC-Bridge detects this and returns HTTP 501 with a body of `{"error":"scanner_unavailable","hint":"..."}` or `{"error":"collaborator_unavailable","hint":"..."}`. This was verified during build-time smoke testing.

**Caveat:** the trial did not include a lab that required either endpoint, so the *downstream agent behavior* on 501 — does the agent recognize the gate and stop, or does it spin — was not tested under this trial. The originally specified SSRF/XXE lab was not run. This is a gap in the validation, not in the bridge itself.

### 5.2 Manual cookie/CSRF handling

v0.1 does not opt into Montoya's cookie jar (`RequestOptions.requestOptions().withCookieJar(true)` or equivalent). Every authenticated call in this trial passed `Cookie: session=...` explicitly. This added approximately 1 line of Python extraction and 1 line of shell variable assignment per session rotation. Across the four labs there were ~10 session rotations total.

This is a deliberate v0.1 design choice (explicit state is easier to audit in writeups) but it does add friction. v0.2 should expose an opt-in.

### 5.3 Full response bodies always returned

Every `/send` and `/repeat` returns the complete response body in the JSON envelope. On Lab 2 this meant ~11 KB × 139 = ~1.5 MB of HTML was shipped from the bridge to the driver, of which ~50 bytes (the `"Welcome back"` substring check) was actually consumed. At lab-tunnel latencies this is negligible; at high-throughput local-target rates it would matter.

### 5.4 No server-side extraction

There is no endpoint that runs a regex or JSONPath against the response body server-side. All extraction happens in the driver after the full body is returned. This is a code-organization issue more than a correctness issue, but it pushes parsing complexity into the caller.

### 5.5 No streaming, no WebSockets, no large-payload testing

The trial did not exercise the bridge on responses larger than ~12 KB or on non-HTTP protocols. CC-Bridge v0.1 has no WebSocket support; if a lab required it, GUI fallback would be needed.

### 5.6 No concurrency tested

All 203 calls in the trial were sequential. The HTTP server's 4-thread executor was never under contention. Whether parallel `/send` calls retain Burp's history ordering or interleave Proxy entries cleanly is unverified.

### 5.7 Trial sample size

Four labs, three of them Apprentice, one Practitioner. No Expert-difficulty labs. No labs with file upload, WebSockets, multi-host scope, or upstream proxy chains. The bridge is validated for workflows resembling these four labs; broader claims are not supported by this dataset.

---

## 6. v0.2 backlog

Ranked by concrete impact observed during the trial. "Saves N calls" means calls eliminated; "saves M minutes" means wall time saved. Items that would only have polished the writeup or saved a few lines of driver code are still listed but flagged.

| Rank | Item | Concrete impact in this trial | Justification |
|---:|---|---|---|
| 1 | **`useCookieJar: true` flag on `/send` and `/repeat`** | Would have eliminated explicit cookie threading on Labs 1, 3, 4. Saves ~10 lines of shell/Python across the trial. Saves 0 calls. | Friction reducer for transactional workflows. Pattern repeats every login-bearing lab; cumulative cost grows with engagement length. |
| 2 | **`POST /extract` — run a regex or JSONPath against a stored response server-side** | On Lab 2, would have shrunk 139 × 11 KB transfers to 139 × ~50 B booleans. Estimated wall-time savings at lab-tunnel latencies: negligible. At local-target rates: potentially 10–20%. | Bigger value is code organization — pushes parsing into a stable API surface instead of driver-specific Python. Saves 0 calls but improves cross-language driver authoring. |
| 3 | **`POST /login` helper that wraps GET /login + extract CSRF + POST /login in one bridge call** | Would have collapsed steps 1–2 in Labs 1, 3, 4 (3 labs × 2 calls = 6 calls saved). | Common enough to justify a helper. Risk: hard-codes assumptions about login form shape (`name=csrf`, etc.). Should be opt-in, not the default. |
| 4 | **Forced-501 downstream agent test** | Not a code change — a methodology addition. The trial as specified included an SSRF lab to verify graceful 501 propagation through the driver and into agent reasoning. That lab was not run. | Until exercised, no claim can be made that the 501 pathway works *in context*. |
| 5 | **`/sitemap` endpoint exposing Burp's site map** | Zero calls saved in this trial — no lab needed it. | Recon-heavy real engagements would benefit. Speculative for now. |
| 6 | **`/match-replace` endpoint** | Zero calls saved in this trial. | Useful for global header/cookie injection in long sessions; would obviate ~30% of Lab 3's cookie-passing if combined with item 1. |
| 7 | **Response body size cap with `?bodyLimit=N` query param** | Zero calls saved. Optional polish for future high-throughput labs. | Not justified by trial data. |
| 8 | **Structured logging of bridge calls to a JSONL file** | Not call-saving. Would have replaced manual call counting in this writeup. | Methodology improvement for future trials. |

**Summary of v0.2 priorities by call savings:**

- Item 3 (login helper) is the only one that demonstrably reduces call count in this trial — by 6 across three labs.
- Items 1, 2, 5–8 reduce friction or improve auditability but do not reduce call count on the workflows observed.
- Item 4 is a test methodology gap to close before the next trial.

---

## 7. Conclusions

### 7.1 What the bridge is validated for

Based on the four-lab trial:

- **`POST /send` as a general-purpose HTTP execution primitive.** Exercised across four labs and ~203 calls without observed failure. Returns full request and response with stable history IDs. Outbound requests appear in Burp's Proxy history identically to manually issued Repeater requests.
- **`POST /repeat/{id}` under sustained iteration.** 139 sequential calls in 23.3 seconds with no dropped responses, no UI lag, no timeouts.
- **Bearer-token authentication on `127.0.0.1`.** Token file workflow (load extension → write `~/.cc-bridge-token` → driver reads → `Authorization: Bearer <token>`) functioned correctly across multiple Burp restarts and one extension reload.
- **501 fallback for Pro-only features.** The error path returns a JSON body with `error` and `hint` fields instead of throwing a 500/NPE. Verified at build time; not verified end-to-end through an agent driver.
- **Workflow patterns:** recon-then-exploit, transactional state machine, iterative oracle, and identity-switch. The bridge is the right shape for all four.

### 7.2 What the bridge is *not* tested for

- Scanner-fed workflows (`/scan`, `/issues`) in a solve context.
- Collaborator-dependent workflows in a solve context. The forced-501 SSRF lab was not run.
- Bodies larger than ~12 KB.
- Concurrent `/send` calls.
- WebSocket-based labs (no support in v0.1; would require GUI fallback).
- File-upload-heavy workflows.
- Multi-host scoping, upstream proxy chains, or non-default Burp session handling rules.
- Long-running engagements where Burp's history grows past the in-memory `HistoryStore` cap (500 entries).
- Token rotation (the trial used the same token throughout).

### 7.3 Defects found

None during the trial. Two paths returned generic NPEs in build-time smoke testing (`/scan` and `/collaborator/new` on Community); both were patched to clean 501s before the trial began and that fix held.

### 7.4 Statement of validation scope

CC-Bridge v0.1 is validated as a localhost HTTP control plane suitable for **scripted, sequential, HTTP-only web-security workflows on Burp Community**, at the scale and shape of PortSwigger Web Security Academy Apprentice and Practitioner labs. It is not validated for the workflows enumerated in §7.2. Validation against a broader matrix — including the items in the v0.2 backlog — requires additional trials.

---

*End of validation report.*
