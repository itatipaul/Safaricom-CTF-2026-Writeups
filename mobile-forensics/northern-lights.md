# Northern Lights — Safcom CTF (iOS / Mobile Forensics, 200 pts)

> *"Some evenings are worth taking slowly. The sky comes alive when the night is at its darkest."*

| | |
|---|---|
| **Challenge** | Northern Lights |
| **Category** | iOS / Mobile forensics + crypto |
| **Points** | 200 (4 likes, 100 %) |
| **Target** | `http://54.72.82.22:8370` |
| **Artefact** | `device-export.zip` (2 317 B) |
| **Decoy** | `safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}` |
| **Flag** | `safctf{3fd96340be891c629f7e3f3a42202743}` (returned by `/submit` — **not** the flag) |

---

## 1. TL;DR

The service hands over `device-export.zip` — an **iOS device/backup export** containing a `Manifest.db`, a `Keychain.plist`, an app preferences plist, a Swift source file, and one sharded backup file. `Persistence.swift` leaks the crypto scheme verbatim:

```swift
// Key = PBKDF2-SHA256(keychain.v_Data + UTF8(account), prefs.salt, prefs.iterations, 32)
// Store: nonce[12] + AES.GCM.sealed + tag[16]
```

Three joins recover the flag:

1. `Manifest.db` resolves the anonymous shard `d4/d443ff…` → `AppDomain.com.northern.lights : Library/Application Support/session.bin`.
2. `com.northern.lights.plist` gives `account`, `salt`, `iterations`.
3. `Keychain.plist` holds **13 items — 12 decoys** (`svce="preview"`) and exactly one whose `acct` equals the app's `account` and whose `svce` is the bundle id. That one's `v_Data` is the key material.

`PBKDF2-SHA256(v_Data ‖ UTF8(account), salt, iterations, 32)` → AES-256-GCM open of `session.bin` → the flag.

**`/submit` is a decoy for this challenge too** — see §7.

---

## 2. Recon

```
$ nmap -Pn -sV -sC -p 8370 54.72.82.22      # (via HexStrike)
8370/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
|_http-title: Northern Lights

$ echo http://54.72.82.22:8370 | httpx -status-code -title -tech-detect -web-server -silent
http://54.72.82.22:8370 [200] [Northern Lights] [Werkzeug/3.1.9 Python/3.11.16] [Flask:3.1.9,Python:3.11.16]
```

The landing page is the same house template as the sibling challenges (one host, one port each), advertising a single download:

```html
<a class="download" href="/downloads/device-export.zip">device-export.zip</a>
```

plus the same inline JS answer-checker at `POST /submit` (`{"answer": "..."}`). The card again says *"Keep your collection receipt when your visit is complete."*

```
$ curl -O http://54.72.82.22:8370/downloads/device-export.zip     # 2 317 B
```

---

## 3. The export

```
$ unzip -l device-export.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8192  2026-10-01 03:59   Manifest.db
     1101  2026-10-01 03:59   Keychain.plist
      127  2026-10-01 03:59   Library/Preferences/com.northern.lights.plist
       72  2026-10-01 03:59   d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607
      137  2026-10-01 03:59   Persistence.swift
```

The shape is unmistakably **iOS**, not Android: `Manifest.db` + `Keychain.plist` + `Library/Preferences/*.plist` is the iOS backup / app-container layout, and the odd two-character directory (`d4/`) is the iOS-backup convention of sharding a file by the first two hex digits of its `fileID` (here a SHA-1 of the domain + relative path).

### 3.1 `Persistence.swift` — the whole crypto spec

```swift
// Key = PBKDF2-SHA256(keychain.v_Data + UTF8(account), prefs.salt, prefs.iterations, 32)
// Store: nonce[12] + AES.GCM.sealed + tag[16]
```

Two lines that reduce the challenge to *finding the inputs*: a PBKDF2 password built by **concatenating raw keychain bytes with a UTF-8 account string**, an app-supplied salt and iteration count, and a standard AES-GCM sealed box with a 12-byte nonce and 16-byte tag.

### 3.2 `Manifest.db` — what is that shard file?

```sql
CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
```

One row:

```
fileID   : d443ff447a8bfaa462b13d797ce4b9ad0142c607
domain   : AppDomain.com.northern.lights
relativePath : Library/Application Support/session.bin
flags    : 1
file     : <66-byte plist>  ->  {'ProtectionClass': 4}
```

So `d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607` is `session.bin`. The inline `file` BLOB is only iOS file-protection metadata (`ProtectionClass 4` = `NSFileProtectionCompleteUntilFirstUserAuthentication`), **not** the payload — a nice misdirection, since on real iOS 10+ backups that BLOB *does* carry the file contents.

```
$ xxd d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607
... 72 bytes total
```

72 B = **12 nonce + 44 sealed + 16 tag**, matching `Persistence.swift` exactly. As with the sibling challenge, the 44-byte sealed length already implies a 44-character plaintext — `safctf{` + 36-char UUID + `}`.

### 3.3 `com.northern.lights.plist` — the KDF parameters

Binary plist:

```python
account    = '18485ad7d74ed05fad7e518b'          # 24-char hex string, UTF-8 in the KDF
iterations = 24000
salt       = b'\x00\x07\x8d(\xe7\x1f\x06\x97\x1fE\xd9\x14\xa5\xbb3\x87'   # 16 raw bytes
```

Note the salt is **already raw bytes** in the plist — no hex-decoding step here, unlike the Android sibling where the salt was hex text.

### 3.4 `Keychain.plist` — the needle in the haystack

13 keychain items. **12 of them are decoys** sharing `svce="preview"` with plausible-looking `acct` values and 32-byte `v_Data`:

```
svce='preview'  acct='1ca253ca2195642963e59e17'  v_Data=47be3da0...
svce='preview'  acct='3f9f2a6f1d76c5109e15603e'  v_Data=4be5c165...
...  (10 more)
svce='com.northern.lights'  acct='18485ad7d74ed05fad7e518b'  v_Data=8093f80ee6ea08331dab7a447ef56af0054517ab3b757074f94cd970ace4d235
```

Only the last one matters, and it is uniquely identified **twice over**:

* its `svce` is the app bundle id `com.northern.lights` (all decoys are `preview`), and
* its `acct` is byte-for-byte the `account` value from the app preferences.

That `acct == prefs.account` join is the intended discriminator. The 12 decoys exist to punish a solver who grabs "the keychain secret" without joining it to the app preference.

**Key material:**
```
v_Data = 8093f80ee6ea08331dab7a447ef56af0054517ab3b757074f94cd970ace4d235
```

---

## 4. Deriving the key and opening the store

The password is a **byte concatenation**, not a formatted string:

```python
import hashlib, plistlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

prefs = plistlib.load(open("Library/Preferences/com.northern.lights.plist", "rb"))
kc    = plistlib.load(open("Keychain.plist", "rb"))

account, salt, iters = prefs["account"], prefs["salt"], prefs["iterations"]
item  = next(i for i in kc["items"] if i["acct"] == account)
vdata = item["v_Data"]                       # 32 raw bytes

password = vdata + account.encode()          # keychain.v_Data + UTF8(account)
key = hashlib.pbkdf2_hmac("sha256", password, salt, iters, 32)
# f6133f202b278970b927f2e9a6cc9bd0f5f3b73aa23d7c2ab471736b1ed4a863

store = open("d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607", "rb").read()
nonce, sealed, tag = store[:12], store[12:-16], store[-16:]
print(AESGCM(key).decrypt(nonce, sealed + tag, None).decode())
```

Output:

```
safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}
```

No AAD. GCM authentication means a successful open is *proof* that every input (the right keychain item, the right salt encoding, the right concatenation order) was correct — no guessing.

---

## 5. Negative controls

| variant | result |
|---|---|
| `v_Data ‖ UTF8(account)`, raw-byte salt, 24000 | ✅ **opens** |
| `UTF8(account) ‖ v_Data` (order swapped) | tag failure |
| `account` omitted (v_Data alone) | tag failure |
| any of the 12 `svce="preview"` items' `v_Data` | tag failure |
| `iterations` from a decoy (e.g. 12000) | tag failure |
| hex-text salt instead of raw bytes | tag failure |

Exactly one combination authenticates — the flag is uniquely determined, not selected from candidates.

---

## 6. Attack-chain summary

```
GET / ────────► landing page; /downloads/device-export.zip + POST /submit API
      │
      └─ device-export.zip
           ├─ Persistence.swift .......... KDF spec: PBKDF2-SHA256(v_Data + UTF8(account),
           │                                          salt, iterations, 32)
           │                              store spec: nonce[12] + AES.GCM.sealed + tag[16]
           ├─ Manifest.db ............... d443ff44… -> AppDomain.com.northern.lights :
           │                              Library/Application Support/session.bin
           ├─ Library/Preferences/com.northern.lights.plist
           │      account    = 18485ad7d74ed05fad7e518b
           │      salt       = 00078d28e71f06971f45d914a5bb3387
           │      iterations = 24000
           ├─ Keychain.plist ............ 13 items; join acct == prefs.account
           │      → svce=com.northern.lights
           │        v_Data = 8093f80ee6ea08331dab7a447ef56af0054517ab3b757074f94cd970ace4d235
           └─ d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607 ......... 72 B store
                      │
                      ▼
       key = PBKDF2-SHA256(v_Data ‖ UTF8("18485ad7d74ed05fad7e518b"), salt, 24000, 32)
                      │
                      ▼
       AES-256-GCM open  ──► safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}   ← FLAG
                      │
       POST /submit ──────► {"ok":true,"message":"safctf{3fd96340...}"}  ← DECOY
```

---

## 7. ⚠️ The `/submit` endpoint is a decoy

```json
POST /submit
{"answer":"safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}"}

→ 200 {"message":"safctf{3fd96340be891c629f7e3f3a42202743}","ok":true}
```

Ignore that `message`. Evidence, identical to the pattern seen on the sibling challenges:

1. **Validates by value, not shape** — well-formed wrong answers are rejected:
   ```
   {"answer":"WRONG"}                                              → 403 {"ok":false}
   {"answer":"safctf{00000000-0000-0000-0000-000000000000}"}       → 403 {"ok":false}
   ```
2. **Hard-coded / stable** — three consecutive submissions returned a byte-identical string.
3. **Not derivable from the input** — `3fd96340be891c629f7e3f3a42202743` ≠ `md5("safctf{5068e894-…}")` (`0f8346ae33fb767ad641fa691e4bc87a`), ≠ `sha256(...)[:32]` (`dae8872250ec69053ba8592aca2ed63c`), ≠ the receipt's own UUID bytes (`5068e89435424574ad651a5bfddd75eb`).
4. **Doesn't accept itself** — feeding the returned flag back in yields `403 {"ok":false}`. A genuine flag endpoint accepts its own flag; this one refuses. Conclusive.
5. **The artefact already contained a flag** — `session.bin`'s plaintext *is* `safctf{...}`.

**Report `safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}`.**

> This is a **recurring platform pattern**, now observed on three Safcom challenges: **Second Pressing** (`:8460`), **Comeback Pocket** (`:8360`), and here. Each accepts the correct receipt and answers with a stable, non-derivable, self-rejecting `safctf{…}` string. On **Matchday Replay** (`:8450`) the reply *was* authoritative — so it must be checked per challenge, never assumed.

---

## 8. Full solve script

`solve.py` — end-to-end, zero manual steps:

```python
#!/usr/bin/env python3
"""Northern Lights (Safcom CTF) - full automated solve."""
import io, sys, hashlib, sqlite3, plistlib, urllib.request, zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8370"
OUT = Path("x"); OUT.mkdir(exist_ok=True)

# 1. acquire + extract
zp = urllib.request.urlopen(BASE + "/downloads/device-export.zip", timeout=60).read()
zipfile.ZipFile(io.BytesIO(zp)).extractall(OUT)

# 2. Manifest.db -> the sharded store file
fid, domain, relpath, flags, meta = sqlite3.connect(OUT / "Manifest.db").execute(
    "select fileID, domain, relativePath, flags, file from Files").fetchone()
store = (OUT / fid[:2] / fid).read_bytes()

# 3. app preferences -> KDF parameters
prefs = plistlib.load(open(OUT / "Library/Preferences/com.northern.lights.plist", "rb"))
account, salt, iters = prefs["account"], prefs["salt"], prefs["iterations"]

# 4. keychain -> the item whose acct joins to prefs.account
kc = plistlib.load(open(OUT / "Keychain.plist", "rb"))
vdata = next(i["v_Data"] for i in kc["items"] if i["acct"] == account)

# 5. PBKDF2-SHA256(v_Data || UTF8(account), salt, iterations, 32)
key = hashlib.pbkdf2_hmac("sha256", vdata + account.encode(), salt, iters, 32)

# 6. AES-GCM open: nonce[12] + sealed + tag[16]
nonce, sealed, tag = store[:12], store[12:-16], store[-16:]
print("FLAG:", AESGCM(key).decrypt(nonce, sealed + tag, None).decode())
```

Run:

```
$ python3 solve.py
FLAG: safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}
```

---

## 9. Lessons / reusable technique

* **`d4/d443ff…` is an iOS backup, not a stray directory.** The two-hex-char shard folder is the `fileID[:2]` convention; `Manifest.db` is the index that turns it back into a real path. Always join before guessing.
* **iOS backup triage order:** `Manifest.db` (what's here) → app plists (parameters) → `Keychain.plist` (secrets) → the payload file.
* **Join the keychain item to the app, don't just take "the secret."** 12 of 13 items were decoys; the discriminator was `acct == prefs.account` (corroborated by `svce == bundle id`). This is the challenge's real trap.
* **`v_Data + UTF8(account)` is a byte concatenation** — Swift's `Data + Data`, not a formatted `"\(a):\(b)"` string. Raw bytes go in, the string is UTF-8 encoded, order matters. Each wrong variant fails the GCM tag, which is the oracle that confirms you got it right.
* **Salt encoding is per-artefact.** Here the salt was already raw bytes in the plist; in the Android sibling it was hex text needing decoding. Read the type, don't pattern-match from the last challenge.
* **A 66-byte inline `file` BLOB in `Manifest.db` is a red herring** on synthetic exports — it's protection metadata, not content.
* **Verify a service's "flag" before reporting it.** Derivable? Stable? Self-accepting? The decoy fails all three.
