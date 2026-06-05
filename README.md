# CC-Bridge

[![Latest release](https://img.shields.io/github/v/release/larrypeseckis/burp-cc-bridge?label=release&color=blue)](https://github.com/larrypeseckis/burp-cc-bridge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Burp Community](https://img.shields.io/badge/Burp-Community-orange.svg)](https://portswigger.net/burp/communitydownload)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-red.svg)](https://adoptium.net/)

A Burp Suite (Montoya API) extension that exposes Burp's most useful primitives over a
localhost HTTP API so an agentic coding shell (Claude Code, OpenAI Codex, etc.) can drive
Burp from `curl`.

Works on Burp Community.

## Download

Grab the latest release JAR — no clone or build required:

**→ [cc-bridge-0.1.0.jar](https://github.com/larrypeseckis/burp-cc-bridge/releases/download/v0.1.0/cc-bridge-0.1.0.jar)** *(381 KB · sha256 `10e21b82a602e43df62ffa2758ef3f51a24af8e1a04affa82ef12d02bde9192c`)*

All releases: <https://github.com/larrypeseckis/burp-cc-bridge/releases>

For validation results across 7 PortSwigger Web Security Academy labs spanning 6 vulnerability classes (250 cc-burp calls, 6 solves, 1 documented architectural boundary, 0 GUI fallbacks), see [VALIDATION.md](VALIDATION.md).

## Build from source

```bash
mvn clean package
# -> target/cc-bridge-0.1.0.jar  (shaded fat JAR)
```

## Install

1. Open Burp → Extensions → Installed → Add.
2. Type **Java**, point at `target/cc-bridge-0.1.0.jar`, click Next.
3. The Output tab should print:
   ```
   CC-Bridge listening on http://127.0.0.1:1337
   Auth token written to ~/.cc-bridge-token (mode 600)
   ```
4. From a shell:
   ```bash
   curl -sH "Authorization: Bearer $(cat ~/.cc-bridge-token)" http://127.0.0.1:1337/health
   ```

Override bind host/port at JVM args (Extension settings → JVM properties):
`-Dccbridge.host=127.0.0.1 -Dccbridge.port=1337`

## API

| Verb | Path | Body / Query |
|------|------|---|
| GET  | `/health` | – |
| POST | `/send` | `{method,url,headers?,body?}` or `{raw, host, port, tls}` |
| GET  | `/history` | `host=`, `method=`, `status=`, `contains=`, `source=proxy|store|all`, `limit=` |
| GET  | `/history/{id}` | – |
| POST | `/repeat/{id}` | `{headers?, removeHeaders?, body?, method?, url?}` |
| POST | `/decode` | `{input, kind: auto|b64|b64url|url|hex|jwt|gzip}` |
| POST | `/scan` | `{url|historyId, type: active|passive}` |
| GET  | `/scan/{taskId}` | – |
| DEL  | `/scan/{taskId}` | – |
| GET  | `/issues` | `host=`, `severity=HIGH|MEDIUM|LOW|INFORMATION` |
| POST | `/collaborator/new` | – |
| POST | `/collaborator/{ctx}` | mint another payload on existing ctx |
| GET  | `/collaborator/{ctx}` | poll interactions |

All endpoints require `Authorization: Bearer <token>`.

## Shell wrapper

```bash
./cc-burp health
./cc-burp send -d '{"method":"GET","url":"https://example.com/"}'
./cc-burp history 'host=example.com&limit=10'
./cc-burp 'history/42'
./cc-burp 'repeat/42' -d '{"headers":{"X-Spoof":"1"}}'
./cc-burp 'collaborator/new' -X POST
```

## Notes

- Outbound requests go through Burp's HTTP client, so they show in Proxy history and
  respect scope, upstream proxies, and session-handling rules.
- The token is regenerated only if `~/.cc-bridge-token` is missing or empty. Delete it
  to rotate.
- Bind is `127.0.0.1` by default — never expose this to the network.
