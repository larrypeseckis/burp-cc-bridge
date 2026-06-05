---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - information-disclosure
  - debug-page
  - phpinfo
  - html-comments
  - environment-variables
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Apprentice
platform: Web Security Academy
date: 2026-06-04
status: Solved ✅
bridge_version: 0.1.0
flags:
  flag: 8elmft6fzl3udkgy49edpr3ymz4pmctq (SECRET_KEY from /cgi-bin/phpinfo.php)
---

## Lab: Information disclosure on debug page

**Class:** Information disclosure / source-comment leak / unprotected debug endpoint
**Bridge endpoints used:** `/send`, `/history/{id}`, **`/history` (list with `contains=` search)**
**Bridge endpoints that failed:** none in v0.1 surface
**Total cc-burp calls:** 7 (1 home + 1 /history/{id} inspect + 1 robots-probe + 1 phpinfo fetch + 1 submit + 1 verify + 1 /history list validation)
**Time to solve:** ~2 minutes wall time
**GUI fallback needed:** No
**Solve chain:** see numbered steps below
**Notable bridge behavior:** **First solve-context use of `/history` (list) with the `contains=` query parameter.** A single call (`cc-burp history 'contains=SECRET_KEY&limit=5'`) correctly identified history id 12 (the phpinfo response) as the only request whose body contained the substring `SECRET_KEY`. This was the last Community-reachable bridge endpoint that had not been exercised in a solve context.

---

# Information disclosure on debug page — Web Security Academy

## Summary

The shop's homepage HTML contains a single commented-out link: `<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->`. The endpoint is live and unauthenticated, serving the full output of PHP's `phpinfo()` — including the application's environment variables. One of those, `SECRET_KEY=8elmft6fzl3udkgy49edpr3ymz4pmctq`, is the lab's solve value. Submitting it via `/submitSolution` trips the lab-solved marker.

The whole lab is two `/send` calls past the recon. The interesting bridge angle is that the writeup also validated `/history` list-with-substring-search, which had been smoke-tested only across the prior eight labs of the trial.

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | `widgetcontainer-lab-status is-solved` + `<p>Solved</p>` |
| `/submitSolution` response | `{"correct":true}` |
| Recovered secret (`$_SERVER['SECRET_KEY']`) | `8elmft6fzl3udkgy49edpr3ymz4pmctq` |
| Disclosure source | HTML comment in `GET /` → `/cgi-bin/phpinfo.php` |

---

## Enumeration

```bash
LAB=https://0ad700f303bb4d48804c94ca00cd000f.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab + grab homepage into history
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>Information disclosure on debug page</title>
# stored as history id=10
```

---

## Step 1 — Read the homepage's HTML comments

The fast approach is to fetch `/history/{id}` and scan for `<!-- ... -->` patterns rather than re-requesting:

```bash
$CC 'history/10' | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
body = d['response']['body']
for m in re.finditer(r'<!--(.*?)-->', body, re.S):
    s = m.group(1).strip()
    if s and 'LAB_' not in s and 'inset' not in s.lower():
        print('comment:', repr(s[:200]))
"
```

```
comment: '<a href=/cgi-bin/phpinfo.php>Debug</a>'
```

One non-template-machinery comment, and it's the entire bug. A "Debug" link, commented out in HTML, still leaks the URL — and the endpoint behind it is live.

> [!tip]
> **Comments are part of the HTTP response. Commenting out a link does not hide it from anyone who reads the source.** This is one of those bugs that feels too simple to be real, and then you find it on real engagements roughly every quarter. Always do at least one pass of `<!--.*?-->` extraction across every HTML response. The 30 seconds of code recovers years of UI rework where someone "removed" a debug feature by HTML-commenting it.

I also probed `/robots.txt` (404 — not the leak path here) before moving on. Worth a single call to rule out the canonical disclosure surface.

---

## Step 2 — Fetch `/cgi-bin/phpinfo.php`

```bash
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/cgi-bin/phpinfo.php\"}"
# 200, 72077 bytes — full PHP info() output
```

72 KB of disclosure. Greppable for whatever you want — interesting things in a real engagement include `DOCUMENT_ROOT`, `_SERVER` keys, loaded extensions, `phpinfo()`-revealed file paths, and any custom env var the operator set. Here the lab signal is the custom `SECRET_KEY` env var:

```python
for m in re.finditer(r'(SECRET|FLAG|LAB|KEY|TOKEN)[A-Z_]*\\s*</td>\\s*<td[^>]*>([^<]+)<', body):
    print(m.group(0)[:200])
# SECRET_KEY </td><td class="v">8elmft6fzl3udkgy49edpr3ymz4pmctq <
```

The value appears twice in the phpinfo output — once in the "Environment" table and once in the `$_SERVER` table. Both have the same value; either match works.

> [!important]
> **Putting secrets in environment variables is fine until you expose the environment.** The original sin here isn't `SECRET_KEY` in `$_SERVER` — that's a perfectly normal way to feed secrets to a PHP app. The sin is shipping `phpinfo()` on a production-reachable URL. The two compose into a disclosure that's worse than either alone. Lock down debug endpoints by default; assume any leaked debug path is a credential-disclosure path.

---

## Step 3 — Submit and verify

```bash
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/submitSolution\",
  \"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\"},
  \"body\":\"answer=8elmft6fzl3udkgy49edpr3ymz4pmctq\"
}"
# 200 {"correct":true}

$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# is-solved + <p>Solved</p>
```

Lab solved.

---

## Step 4 (bonus) — Validate `/history` list with `contains=` substring search

The endpoint exists in v0.1 but had only been smoke-tested. Closing it out in a real solve context took one call:

```bash
$CC 'history' 'contains=SECRET_KEY&limit=5'
```

```json
{
  "count": 1,
  "items": [
    {
      "id": 12,
      "source": "store",
      "request": {"method": "GET", "host": "0ad700f303bb4d48804c94ca00cd000f.web-security-academy.net", "path": "/cgi-bin/phpinfo.php"}
    }
  ]
}
```

One hit. Correctly identified as the phpinfo response. The substring scan ran against both stored entries (via `/send`) and Burp's proxy history. The endpoint is now validated for the substring-search workflow it was designed for.

---

## Attack Chain Summary

```
GET /                                       -> store homepage at history id=10
GET /history/10 (bridge)                    -> extract HTML comments, find /cgi-bin/phpinfo.php
GET /robots.txt                             -> 404 (ruled out canonical disclosure surface)
GET /cgi-bin/phpinfo.php                    -> 72 KB phpinfo, SECRET_KEY=8elm…ctq
POST /submitSolution answer=<secret>        -> 200 {"correct":true}
GET /                                       -> is-solved
GET /history?contains=SECRET_KEY&limit=5    -> 1 hit, id=12 (validation bonus)
```

---

## Key Concepts

**The HTML comment "fix" pattern is a stable bug factory.** Developers asked to "remove a debug feature for production" frequently HTML-comment the link rather than deleting the route, the handler, the page template, *and* the URL pattern. Three of those four still ship; the link is invisible in the rendered DOM but trivially recoverable from view-source. Same pattern in JavaScript: `// const ADMIN_URL = ...` leaves the constant string parseable by anyone reading the source. The "removal" is performative; the artifact persists.

**`phpinfo()` is RCE-adjacent without being RCE.** A leaked phpinfo gives an attacker (a) every environment variable, including secrets fed via env, (b) the full PHP configuration including loaded extensions and `open_basedir`/disable_functions/etc., (c) file paths to the application source, (d) the PHP version (vuln-list lookup), (e) every HTTP header the request carried. From there a directed attack — credential reuse, deserialization gadget selection, traversal targeting — is a short walk. The right production posture is: phpinfo never on a routable URL, period.

**Reading from `/history/{id}` is cheaper than re-requesting.** When the response body is already in the bridge's store from an earlier call, fetching it back via `/history/{id}` is free relative to re-issuing the request — and it preserves the original timing, headers, and any one-time state. Useful for iterative recon where you want to re-grep the same body with different patterns.

**The `/history` list with `contains=` is the late-game recon primitive.** As a solve grows in call count, the question "where did I see X?" becomes the bottleneck. The bridge's list endpoint scans request *and* response bodies in the in-memory store plus Burp's proxy history for a substring match. One call resolves a question that would otherwise require either re-issuing requests or scrolling Burp's UI. This is the endpoint that comes into its own on multi-step labs and real engagements, not on this tiny disclosure lab — but the substring-search code path is the same shape regardless of scale.

**Two-call labs are still useful trial data.** Every prior trial lab burned at least 5 calls. This one is 4 essential calls plus 3 incidental (history inspect, robots check, validation bonus). The bridge's overhead per call (~10–20 ms) is invariant to lab complexity, so cheap labs round-trip in seconds. The interesting observation is the consistency: no setup cost beyond the first call, no bridge-side warm-up, no "slow first request."

---

## Detection / Defense

| Control | What it Prevents |
|---|---|
| Remove debug routes from production builds entirely — don't ship the handler, don't ship the URL pattern | The whole class of debug-page disclosures |
| If debug pages must exist, gate them behind environment-aware middleware: refuse to render when `APP_ENV=production` or when the request didn't come from a known internal CIDR | Exposed-but-protected debug endpoints |
| HTTP auth or mTLS on any URL containing `/debug`, `/admin`, `/cgi-bin`, `/_internal` | Defense in depth for paths that escape the first rule |
| Never set secrets via env when the application can echo `$_SERVER` / `printenv` / `phpinfo()` — use file-mounted secrets read at startup and unset from the process env immediately | `phpinfo()`-style env disclosure even if the debug endpoint leaks |
| Web-server level: explicitly disable PHP execution under any path matching `/cgi-bin/` if not actively used, or remove the CGI handler entirely | The general case: arbitrary `.php` under `/cgi-bin/` becoming executable code |
| Source-code linter rule: flag every HTML comment containing `href=` or `src=` for review before merge | Catches the "comment-out instead of remove" pattern at the development boundary |
| WAF rule that drops responses larger than 50 KB containing the string `phpinfo()` | Detection if a regression ships phpinfo to a public URL |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| `/robots.txt` | 404 — the disclosure isn't here |
| `/sitemap.xml`, `/.well-known/*`, `/admin`, `/api/debug` | Not probed — the HTML comment surfaced the path on the first read |
| `/scan` for auto-detection | 501 on Community |
| `/decode`, `/repeat`, `/collaborator` | Not applicable |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 5 | All worked (home, robots, phpinfo, submit, verify) |
| `POST /repeat/{id}` | 0 | – |
| `GET /history/{id}` | 1 | Used to re-read homepage HTML for comment extraction without re-requesting |
| **`GET /history`** | **1** | **First solve-context use** of the list endpoint with `contains=` substring search. One hit, correctly identified as id=12 (phpinfo response). Endpoint now validated for the workflow it was designed for. |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `POST /collaborator/new` | 0 | – |

**Coverage milestone:** with this lab, every Community-reachable bridge endpoint has been exercised in a solve context at least once. Previously:

- `/send` — every lab
- `/repeat/{id}` — Labs 2 (iteration), 5 (exploration), 6 (header variation)
- `/decode` — Lab 7 (Java deserialization cookie)
- `/history/{id}` — Labs 6 (transmitted-header verification) and 9 (this lab, HTML re-grep)
- **`/history` list — Lab 9 (this lab, substring search)** ← new
- `/collaborator/new` 501 path — Lab 6

The Pro-gated endpoints (`/scan`, `/scan/{taskId}`, `/issues`, `/collaborator/{ctx}` polling) remain unexercised because Burp Community has no underlying capability to wrap. Per Lab 6's analysis, that's the bridge being at parity with Community's actual ceiling, not a coverage gap.

**No bugs surfaced. Nothing to add to v0.2 spec from this lab.**

---

## Lessons Learned

1. **The first call after a home-page fetch is almost always "re-read the response."** Fetching `/history/{id}` instead of re-issuing the request preserves the original timing and avoids cookie churn. This was the right move for the comment-extraction step here, and it generalizes: any time the home page is "the canonical surface to grep against repeatedly," store the id and grep via `/history/{id}`.
2. **`/history` list with `contains=` answers the "where did I see this" question in one call.** Two-call labs don't show its value; ten-call labs start to; hundred-call labs make it essential. Worth keeping in muscle memory: `cc-burp history "contains=<token>&limit=10"`.
3. **PortSwigger labs with `/submitSolution` are scriptable in fewer calls than the lab description implies.** Many Apprentice labs solve in 4–6 calls when the "click around in Burp" instructions are replaced with targeted `/send`s. The `/submitSolution` endpoint is a stable API across the academy; once you've seen it, every "submit the secret" lab collapses to one POST.
4. **HTML comments are the single highest-yield recon primitive per byte of code.** A 60-character regex extracts the bug from the homepage. No traversal, no fuzzing, no wordlist. The "expensive recon" toolkit (gobuster, ffuf, sqlmap, nikto) often misses what `<!-- ... -->` extraction gets in milliseconds.
5. **Closing a smoke-test-only endpoint takes one well-chosen lab.** `/history` list had been the last Community-reachable bridge surface without a solve-context exercise. The right lab for it is one where you'd want to ask "where did I see X" — even if the answer is trivially "the last request." Coverage-by-design pays off here because the call cost of the validation is one bridge call.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane; `/history` list with `contains=` validated in solve context |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Burp Suite Community 2025.x | Hosts the extension, logs every request in Proxy history |
| `python3` (inline) | HTML comment extraction, regex matching against phpinfo tables |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth |
| Burp Suite Community 2025.x | Extension host |
| `python3` (inline) | HTML parsing |

---

*Web Security Academy — Information disclosure on debug page | Solved | CC-Bridge v0.1*
