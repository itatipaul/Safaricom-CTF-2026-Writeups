# Comeback Pocket — Safcom CTF (Android / Mobile Forensics, 150 pts)

> *"One more chorus before the train arrives."*

| | |
|---|---|
| **Challenge** | Comeback Pocket |
| **Category** | Android / Mobile forensics + crypto |
| **Points** | 150 (5 likes, 100 %) |
| **Target** | `http://54.72.82.22:8360` |
| **Decoy** | `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}` |
| **Flag** | `safctf{408e83b586354238e5a8e968a74b8b64}` (returned by `/submit` — **not** the flag) |

---

## 1. TL;DR

The web service serves an **Android Backup (`.ab`) file** plus the app's **`Session.java`** persistence adapter. Unpacking the (unencrypted) backup yields the app's private storage: a SQLite `accounts` table, a SharedPreferences blob holding a **salt** and **iteration count**, and `f/pass.bin` — a raw **AES-256-GCM** blob (12-byte IV ‖ 44-byte ciphertext ‖ 16-byte tag).

`Session.java` hands over the exact key-derivation scheme:

```java
SecretKey load(String uid, String device, byte[] salt) {
  return PBKDF2WithHmacSHA256(uid + ":" + device, salt, 12000, 256);
}
```

The missing inputs are all inside the backup. The `accounts` table has exactly **one row with `active=1`** — that row is the real (uid, device) pair the app would use; the other 30 rows are padding. `session.xml` supplies salt + rounds. Re-implementing the KDF and GCM-decrypting `pass.bin` produces the flag directly off the artefact.

**The `/submit` endpoint is a decoy for this challenge** — details in §7.

---

## 2. Recon

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -sC -p 8360 54.72.82.22
PORT     STATE SERVICE VERSION
8360/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
|_http-title: Comeback Pocket
|_http-server-header: Werkzeug/3.1.9 Python/3.11.16

$ echo http://54.72.82.22:8360 | httpx -status-code -title -tech-detect -web-server -silent
http://54.72.82.22:8360 [200] [Comeback Pocket] [Werkzeug/3.1.9 Python/3.11.16] [Flask:3.1.9,Python:3.11.16]
```

Host resolves to `ec2-54-72-82-22.eu-west-1.compute.amazonaws.com` — a plain Flask app on AWS eu-west-1.

### 2.2 Landing page

The root page is a static-looking "Collection desk" with two downloads:

```html
<a class="download" href="/downloads/Session.java">Session.java</a>
<a class="download" href="/downloads/pocket.ab">pocket.ab</a>
```

Inline JS reveals a single JSON API — an answer checker at `POST /submit`:

```js
let body = JSON.stringify({answer: document.getElementById('answer').value});
let r = await fetch('/submit', {method:'POST', headers:{'Content-Type':'application/json'}, body});
```

The card also nudges the solver: *"Keep your collection receipt when your visit is complete."* — i.e. the artefact itself carries the receipt/flag.

### 2.3 Pulling the material

```bash
curl -O http://54.72.82.22:8360/downloads/Session.java
curl -O http://54.72.82.22:8360/downloads/pocket.ab
# Session.java 219 B ; pocket.ab 1667 B
```

`Session.java` — the whole file:

```java
// Application export: persistence adapter
SecretKey load(String uid,String device,byte[] salt) {
 return PBKDF2WithHmacSHA256(uid+":"+device,salt,12000,256);
}
// pass.bin: 12-byte IV, AES/GCM ciphertext, 16-byte tag.
```

That comment is the entire crypto spec: **PBKDF2-HMAC-SHA256**, password `uid:device`, 12000 rounds, 256-bit key, and a `pass.bin` that is IV‖CT‖TAG.

---

## 3. Unpacking the Android Backup

```
$ file pocket.ab
pocket.ab: Android Backup, version 5, Compressed, Not-Encrypted
```

The `.ab` container format is text-header + payload:

```
ANDROID BACKUP\n    magic
5\n                 version
1\n                 compressed (1 = zlib)
none\n              encryption algorithm
<zlib-compressed tar>
```

Because encryption is `none`, no backup password is needed — just strip the four header lines and inflate. No third-party tool required (`adb backup`/`abe` work too, but 15 lines of Python is enough and avoids version-dependent `abe` behaviour with v5 headers).

```python
import zlib, tarfile, io
raw = open('pocket.ab','rb').read()
idx = 0
for _ in range(4):                       # magic, version, compressed, encryption
    idx = raw.index(b'\n', idx) + 1
data = zlib.decompress(raw[idx:])
tarfile.open(fileobj=io.BytesIO(data)).extractall('ab')
```

Resulting tree:

```
apps/com.comeback.pocket/_manifest          (50 B)
apps/com.comeback.pocket/sp/session.xml     (158 B)
apps/com.comeback.pocket/f/pass.bin         (72 B)
apps/com.comeback.pocket/db/accounts.db     (8192 B)
```

Decompressed tar size: 20480 B.

---

## 4. Harvesting the KDF inputs

### 4.1 `sp/session.xml` → salt + rounds

```xml
<map>
  <string name="installation">member-2dea8614a9</string>
  <string name="s">67beb4eff155c1bff95be68fd8c2e4e0</string>
  <int name="rounds" value="12000" />
</map>
```

* `s` = 32 hex chars = **16-byte salt** → `67beb4eff155c1bff95be68fd8c2e4e0`
* `rounds` = **12000** (matches the hard-coded value in `Session.java` — good confirmation)
* `installation` = `member-2dea8614a9` — a *prefix* of the uid, hinting at which row matters.

### 4.2 `db/accounts.db` → the active (uid, device) pair

```sql
CREATE TABLE accounts(uid TEXT, active INTEGER, device TEXT);
```

31 rows, each a `member-XXXXXXXXXX` uid with a 32-hex `device`. Exactly one row is active:

```sql
sqlite> select uid, active, device from accounts where active = 1;
uid                 active  device
member-2dea8614a9   1       4e13eb4f120b8f4709ee20e57a597758
```

```
uid    = member-2dea8614a9
device = 4e13eb4f120b8f4709ee20e57a597758
```

Two independent signals agree this is the right row: the `active=1` flag, and `session.xml`'s `installation` value matching the uid prefix. **This is the key trap of the challenge** — there are 31 candidate rows, and only the active one yields a valid GCM tag. A solver who brute-forces all 31 finds the same answer, but the `active` column is the intended shortcut.

### 4.3 `f/pass.bin` → the blob

```
$ xxd f/pass.bin
00000000: b56e 41b1 dc6f 3939 60cc 1808 317e 250e  .nA..o99`...1~%.
...
00000040: f23d 91e2 0270 5aa4                      .=...pZ.
```

72 bytes total = **12 IV + 44 ciphertext + 16 GCM tag**, exactly as the `Session.java` comment promised. Splitting:

| part | bytes | value |
|---|---|---|
| IV | 12 | `b56e41b1dc6f393960cc1808` |
| ciphertext | 44 | (bytes 12..56) |
| tag | 16 | `4575cc8ebe22d9ebf23d91e202705aa4` |

The 44-byte ciphertext length is itself a tell: the plaintext is a 44-character string — precisely the length of `safctf{` + 36 UUID chars + `}`.

---

## 5. Recovering the key and decrypting

`PBKDF2WithHmacSHA256` in Java uses the password **string encoded as UTF-8**, so the ASCII password `member-2dea8614a9:4e13eb4f120b8f4709ee20e57a597758` is used directly; the salt is the **raw 16 bytes** obtained by hex-decoding `s` (not the ASCII hex text — that variant fails the GCM tag check, which is a useful negative control).

```python
import hashlib, binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

uid    = "member-2dea8614a9"
device = "4e13eb4f120b8f4709ee20e57a597758"
salt   = binascii.unhexlify("67beb4eff155c1bff95be68fd8c2e4e0")
rounds = 12000

key = hashlib.pbkdf2_hmac("sha256", f"{uid}:{device}".encode(), salt, rounds, 32)
# 75b1c7c0c619849431cea57ca42c1dad3557366f60a3def6a4d8e6fe5463979b

blob = open("f/pass.bin", "rb").read()
iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
print(AESGCM(key).decrypt(iv, ct + tag, None).decode())
```

Output:

```
safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}
```

No AAD is used. GCM is authenticated, so a successful decrypt **is** the correctness proof — no guessing required. The tag verifying also retroactively confirms the (uid, device, salt, rounds, ASCII-vs-hex) choices were all right.

---

## 6. Adversarial alternatives tried (negative controls)

Enumerated to show the key material is uniquely determined, not guessed:

| password | salt form | result |
|---|---|---|
| `uid:device` | **hex-decoded (16 B)** | ✅ **decrypts** |
| `uid:device` | ASCII hex text (32 B) | tag failure |
| `uid:device` | empty | tag failure |
| `device:uid` | hex-decoded | tag failure |
| `device:uid` | ASCII / empty | tag failure |

Only one combination authenticates. (Brute-forcing across all 31 `accounts` rows likewise yields exactly one hit — the `active=1` row.)

---

## 7. ⚠️ The `/submit` endpoint is a decoy

Submitting the recovered receipt:

```json
POST /submit
{"answer":"safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}"}

→ 200 {"message":"safctf{408e83b586354238e5a8e968a74b8b64}","ok":true}
```

That `message` is **not the flag**. Evidence:

1. **It validates by value, not shape.** Well-formed wrong answers are rejected:
   ```
   POST {"answer":"WRONG"}                                      → 403 {"ok":false}
   POST {"answer":"safctf{00000000-0000-0000-0000-000000000000}"} → 403 {"ok":false}
   ```
   So the endpoint genuinely checks the receipt — it just answers with something else.

2. **The reply is hard-coded / stable.** Three consecutive submissions of the same correct answer returned a byte-identical string.

3. **It is not derivable from the input.** The reply's inner hex `408e83b586354238e5a8e968a74b8b64` matches none of:
   * `md5("safctf{ddd6569c-...}")` = `5048d7c6f7e3af5d4717fea0d62fd4f2`
   * `sha256(...)[:32]` = `2a767011f3f064cf3e6ae499a95be5a6`
   * the receipt's own UUID bytes = `ddd6569c76554aa884e8cd7f4acd4f78`

4. **The decoy doesn't even validate itself.** Feeding the returned flag back in:
   ```
   POST {"answer":"safctf{408e83b586354238e5a8e968a74b8b64}"} → 403 {"ok":false}
   ```
   A real flag endpoint would accept its own flag. This one rejects it — conclusive.

5. **The artefact already contained a flag.** The plaintext of `pass.bin` *is* `safctf{...}`. When the recovered artefact is itself a flag, the service's convenience answer is the suspect one.

**Report `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}`.**

> This is a recurring pattern on this CTF platform, not a one-off: the sibling forensics challenge **Second Pressing** (`:8460`) behaves identically — correct receipt → `ok:true` + a hard-coded `safctf{34a793a0d11032abb97236fafc9b30c4}` that the scoring platform rejects. On **Matchday Replay** (`:8450`), by contrast, the `/submit` reply *was* authoritative. So the behaviour is per-challenge: always check whether the reply is derivable, stable, and self-accepting before trusting it.

---

## 8. Full solve script

`solve.py` — end-to-end, no manual steps:

```python
#!/usr/bin/env python3
"""Comeback Pocket (Safcom CTF) - full automated solve."""
import io, sys, zlib, tarfile, hashlib, sqlite3, binascii, tempfile, re
import urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8360"

def fetch(path):
    with urllib.request.urlopen(BASE.rstrip("/") + path, timeout=30) as r:
        return r.read()

# 1. acquire
sj, ab = fetch("/downloads/Session.java"), fetch("/downloads/pocket.ab")

# 2. unpack the Android Backup: header lines then zlib'd tar
idx, fields = len(b"ANDROID BACKUP\n"), []
for _ in range(3):                       # version, compressed, encryption
    j = ab.index(b"\n", idx); fields.append(ab[idx:j].decode()); idx = j + 1
payload = zlib.decompress(ab[idx:]) if fields[1] == "1" else ab[idx:]
tf = tarfile.open(fileobj=io.BytesIO(payload))
members = tf.getmembers()

# 3. the single active account row -> uid, device
tmp = Path(tempfile.mkdtemp()) / "accounts.db"
tmp.write_bytes(tf.extractfile(next(m for m in members
                 if m.name.endswith("db/accounts.db"))).read())
uid, device = sqlite3.connect(tmp).execute(
    "select uid, device from accounts where active=1").fetchone()

# 4. salt + rounds from SharedPreferences
sp = tf.extractfile(next(m for m in members
        if m.name.endswith("sp/session.xml"))).read().decode()
salt   = binascii.unhexlify(re.search(r'name="s">([0-9a-f]+)<', sp).group(1))
rounds = int(re.search(r'name="rounds"\s+value="(\d+)"', sp).group(1))

# 5. PBKDF2WithHmacSHA256(uid+":"+device, salt, rounds, 256)
key = hashlib.pbkdf2_hmac("sha256", f"{uid}:{device}".encode(), salt, rounds, 32)

# 6. AES-GCM decrypt: 12-byte IV || ciphertext || 16-byte tag
blob = tf.extractfile(next(m for m in members
        if m.name.endswith("f/pass.bin"))).read()
iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
print("FLAG:", AESGCM(key).decrypt(iv, ct + tag, None).decode())
```

Run:

```
$ python3 solve.py
FLAG: safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}
```

---

## 9. Attack-chain summary

```
GET /  ─────────────► landing page, two downloads + POST /submit API
   │
   ├─ GET /downloads/Session.java ──► KDF spec: PBKDF2-HMAC-SHA256(uid+":"+device, salt, 12000, 256)
   │                                  blob spec: 12B IV ‖ AES/GCM CT ‖ 16B tag
   │
   └─ GET /downloads/pocket.ab ─────► Android Backup v5, compressed, NOT encrypted
          │  strip 4 header lines → zlib inflate → tar
          ├─ sp/session.xml ........ salt = 67beb4eff155c1bff95be68fd8c2e4e0, rounds = 12000
          ├─ db/accounts.db ........ 31 rows; active=1 → uid=member-2dea8614a9
          │                          device=4e13eb4f120b8f4709ee20e57a597758
          └─ f/pass.bin ............ 12B IV ‖ 44B CT ‖ 16B tag
                    │
                    ▼
        key = PBKDF2("member-2dea8614a9:4e13eb4f120b8f4709ee20e57a597758", salt, 12000)
                    │
                    ▼
        AES-256-GCM decrypt  ──► safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}   ← FLAG
                    │
        POST /submit ────────► {"ok":true,"message":"safctf{408e83b5...}"}  ← DECOY
```

---

## 10. Lessons / reusable technique

* **`.ab` is a trivial container.** Four newline-terminated header lines (`ANDROID BACKUP`, version, compressed flag, encryption algorithm) followed by a zlib-deflated tar when encryption is `none`. Parse it in Python — no `abe`/`adb` needed, and no risk of the extractor checkpointing or rewriting your evidence.
* **Leaked key-derivation code is half the solve.** `Session.java` gave algorithm, password construction, iteration count, key size, and the exact byte layout of the ciphertext file. The challenge reduced to *finding the two inputs* — which is where the difficulty actually lives.
* **`active=1` is a filter, not decoration.** 31 plausible rows, one flagged active, and `session.xml` independently corroborates the uid. Prefer semantic signals over brute force.
* **Pick the right salt encoding.** Hex in config almost always means hex-**decode** the bytes; feeding the ASCII hex string to PBKDF2 is the classic near-miss. GCM's authentication tag turns "did I get it right?" into a boolean oracle.
* **A 44-byte GCM ciphertext screams `safctf{<36-char UUID>}`.** Length analysis alone told us the flag shape before decrypting.
* **Verify a service's "flag" before reporting it.** Checks: is it *derivable* from the input, *stable* across submissions, and *accepted when submitted as the answer*? The Comeback Pocket decoy failed all three. Prefer the artefact-derived value.
