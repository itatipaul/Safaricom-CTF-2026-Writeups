# Glass Arcade — Safcom CTF (Android / Mobile Forensics + crypto, 300 pts)

> *"The lights are bright, the machines are humming, and every screen is waiting for the
> next player. Everything looks transparent from the outside."*

| | |
|---|---|
| **Challenge** | Glass Arcade |
| **Category** | Android / Mobile forensics + crypto |
| **Points** | 300 (4 likes, 100 %) |
| **Target** | `http://54.72.82.22:8380` |
| **Artefacts** | `glass-arcade.apk` (5 309 B), `session.json` (92 B) |
| **Decoy** | `safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}` |
| **Flag** | `safctf{318223415bd0e96e2f63b0dd88eacf2d}` (returned by `/submit`) |

---

## 1. TL;DR

The service hands over two files: a **5 KB APK** and a **92-byte `session.json`**. The APK is
synthetic but complete — a single Activity (`Lobby`), a tiny `classes.dex`, and one asset,
`assets/session.bin`. The whole challenge is *readable from ~30 lines of decompiled Java*:

```java
private String visit(String transfer) {
    byte[] raw = Base64.decode(transfer, 0);              // 16 bytes
    byte[] seed = new byte[16];
    seed[i] = (byte)( (A_i - B_i) ^ raw[i] );             // 16 masks, hard-coded
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(seed);
    SecretKeySpec key = new SecretKeySpec(
            md.digest("glass-arcade/3".getBytes("UTF-8")), "AES");
    byte[] blob = readAsset("session.bin");               // 72 bytes
    GCMParameterSpec spec = new GCMParameterSpec(128, Arrays.copyOfRange(blob, 0, 12));
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(DECRYPT_MODE, key, spec);
    return new String(c.doFinal(Arrays.copyOfRange(blob, 12, blob.length)), "UTF-8");
}
```

Three inputs, one output:

1. **`transfer`** — the base64 string in `session.json` is XORed with a 16-byte mask table baked
   into the dex, producing a 16-byte **seed**.
2. **`SHA-256(seed ‖ "glass-arcade/3")`** — the 32-byte AES key. The trailing `3` is the
   `build` field from `session.json`.
3. **`assets/session.bin`** — `nonce[12] ‖ sealed ‖ tag[16]`, opened with AES-256-GCM (128-bit
   tag, no AAD). The plaintext **is the flag**.

`session.json`'s `account` field is **never referenced anywhere in the dex** — it is a decoy.

`POST /submit` accepts the correct answer and replies with a *different* flag-shaped string.
That string is the recurring platform decoy — see §6.

---

## 2. Recon

```
$ nmap -Pn -sV -sC -p 8380 54.72.82.22          # (via HexStrike)
8380/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
|_http-title: Glass Arcade

$ httpx -u http://54.72.82.22:8380 -status-code -title -tech-detect -web-server -silent
http://54.72.82.22:8380 [200] [Glass Arcade] [Werkzeug/3.1.9 Python/3.11.16] [Flask:3.1.9]
```

Flask/Werkzeug — the same house template as the sibling challenges. Endpoint probe:

| path | result |
|---|---|
| `/` | 200 (3 657 B) |
| `/submit` | **405** on GET → POST-only answer checker |
| `/robots.txt`, `/sitemap.xml`, `/downloads/`, `/files/`, `/static/`, `/assets/`, `/api/`, `/flag`, `/*.zip` | 404 |

The landing page (**"COLLECTION DESK"**) advertises exactly two downloads:

```html
<a class="download" href="/downloads/glass-arcade.apk">glass-arcade.apk</a>
<a class="download" href="/downloads/session.json">session.json</a>
```

`session.json` is the second file the sibling challenges never had — its contents are the
key material for the APK:

```json
{
  "account": "cc8914d136ec62f6",
  "build": 3,
  "transfer": "P9noumCVAhimnBVdDcWUyA=="
}
```

---

## 3. The APK

```
$ unzip -l glass-arcade.apk
     1528  AndroidManifest.xml
       72  assets/session.bin
     3024  classes.dex
      399  META-INF/MANIFEST.MF
     1662  META-INF/STUDIO.RSA
      604  META-INF/STUDIO.SF
```

5 KB total — hand-built, Studio-signed, no libraries. No obfuscation, no native code, no
resources.arsc. The manifest is equally plain:

```
package="com.glass.arcade"  versionCode="3"  versionName="3.0"
<activity android:name=".Lobby" android:exported="true">   ← launcher
```

Note `versionCode=3` — the same **3** that appears in the key-derivation salt.

### 3.1 `classes.dex` — `Lobby.visit()`

`strings` already gives the scheme away:

```
AES/GCM/NoPadding   SHA-256   UTF-8   GCMParameterSpec   SecretKeySpec
MessageDigest       Arrays.copyOfRange   Base64.decode   android/util/Base64
session.bin         transfer   visit   glass-arcade/3
```

Decompiling `Lobby` (androguard) gives two real methods: `onCreate` and `visit`. `onCreate`
is just UI plumbing — it reads the **`transfer`** Intent extra and calls `visit(transfer)`:

```java
public void onCreate(Bundle b) {
    TextView tv = new TextView(this);
    String msg = "Glass Arcade — a bright screen on a rainy afternoon.";
    try {
        String transfer = getIntent().getStringExtra("transfer");
        ...
        tv.setText(visit(transfer));
    } catch (Exception e) { tv.setText(msg); }
    ...
}
```

So `session.json.transfer` is the Intent extra, and `visit` is the crypto.

### 3.2 The mask table

The seed construction is written out longhand, one line per byte:

```java
byte[] seed = new byte[16];
seed[0]  = (byte)(( 80 -  0) ^ raw[0]);
seed[1]  = (byte)((188 -  7) ^ raw[1]);
seed[2]  = (byte)((119 - 14) ^ raw[2]);
...
seed[15] = (byte)((175 - 105) ^ raw[15]);
```

The subtraction is noise — what lands in the bytecode is the **difference**, mod 256:

```
MASK = 50 b5 69 6c bc 55 8e a5 fc 98 ff cd c0 e1 7f 46
```

### 3.3 The key derivation

```java
MessageDigest md = MessageDigest.getInstance("SHA-256");
md.update(seed);                                        // 16-byte XOR seed
SecretKeySpec key = new SecretKeySpec(
        md.digest("glass-arcade/3".getBytes("UTF-8")),  // salt = app name + build
        "AES");
```

`MessageDigest.digest(byte[] input)` is *"update(input), then digest"*, so the preimage is the
**concatenation**:

```
key = SHA-256( seed ‖ "glass-arcade/3" )
```

The `3` is `session.json.build` — the build number is part of the key, which is why the
`versionCode="3"` in the manifest and `"build": 3` in the session agree. (A solver who assumes
a build of 1 or 2 gets a key that fails the GCM tag.)

### 3.4 The payload

```java
byte[] blob  = readAsset("session.bin");                 // 72 bytes
GCMParameterSpec spec = new GCMParameterSpec(128, Arrays.copyOfRange(blob, 0, 12));
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.DECRYPT_MODE, key, spec);
String flag = new String(c.doFinal(Arrays.copyOfRange(blob, 12, blob.length)), "UTF-8");
```

72 B = **12-byte nonce ‖ 44-byte sealed ‖ 16-byte tag** — the same envelope as the sibling
`session.bin`s, and the 44-byte plaintext again implies `safctf{` + 36-char UUID + `}`.
No AAD.

---

## 4. Solving

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sess = json.load(open("session.json"))

pairs = [(80,0),(188,7),(119,14),(129,21),(216,28),(120,35),(184,42),(214,49),
         (52,56),(215,63),(69,70),(26,77),(20,84),(60,91),(225,98),(175,105)]
MASK = bytes((a - b) & 0xFF for a, b in pairs)          # 50b5696cbc558ea5fc98ffcdc0e17f46

raw  = base64.b64decode(sess["transfer"])               # 3fd9e8ba60950218a69c155d0dc594c8
seed = bytes(m ^ r for m, r in zip(MASK, raw))          # 6f6c81d6dcc08cbd5a04ea90cd24eb8e
key  = hashlib.sha256(seed + b"glass-arcade/3").digest()

blob  = open("x/apk/assets/session.bin","rb").read()
nonce, ct = blob[:12], blob[12:]
print(AESGCM(key).decrypt(nonce, ct, None).decode())
```

Intermediate values:

| quantity | value |
|---|---|
| `Base64.decode(transfer)` | `3fd9e8ba60950218a69c155d0dc594c8` |
| `MASK` | `50b5696cbc558ea5fc98ffcdc0e17f46` |
| `seed = MASK ^ raw` | `6f6c81d6dcc08cbd5a04ea90cd24eb8e` |
| `key = SHA-256(seed ‖ "glass-arcade/3")` | `cd097113b5603025cc04b022a5bddd9cc8673e9ed4994abf1246f8b5643a9950` |
| `nonce` | `d9d72859b38348d224a53c79` |
| `sealed+tag` | 60 B |
| **plaintext** | **`safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}`** |

The GCM tag verifies, so every input is confirmed correct — no guessing, and the `account`
field being unused is proven by the decryption succeeding without it.

---

## 5. Attack-chain summary

```
GET / ──────────► "Glass Arcade" landing page (COLLECTION DESK)
      │                 two downloads; POST /submit answer-checker
      │
      ├─ GET /downloads/session.json ──► {account(decoy), build:3, transfer:<b64>}
      │                                                     │
      └─ GET /downloads/glass-arcade.apk ──► 5 KB APK       │
              ├─ AndroidManifest.xml ... com.glass.arcade, versionCode=3, .Lobby
              ├─ classes.dex ........... Lobby.visit(transfer):
              │        raw  = Base64.decode(transfer)       ◄──┘
              │        seed = MASK ^ raw            (16 hard-coded masks)
              │        key  = SHA-256(seed || "glass-arcade/3")   ◄── build=3
              │        nonce = blob[0:12]; ct = blob[12:]
              │        AES/GCM/NoPadding, 128-bit tag, no AAD
              └─ assets/session.bin .... 72 B = nonce[12] ‖ sealed[44] ‖ tag[16]
                          │
                          ▼
              safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}   ← FLAG
                          │
              POST /submit ──► {"ok":true,"message":"safctf{31822341...}"}  ← DECOY
```

---

## 6. ⚠️ `/submit` is a decoy (again)

```json
POST /submit
{"answer":"safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}"}
→ 200 {"message":"safctf{318223415bd0e96e2f63b0dd88eacf2d}","ok":true}
```

All five decoy tests fail on that reply:

| test | result |
|---|---|
| validates **by value** (well-formed wrong answers rejected) | `WRONG` → 403; `safctf{0000…}` → 403 |
| **stable** across submissions | 3× byte-identical `318223415bd0e96e2f63b0dd88eacf2d` |
| **derivable** from our flag | ✗ `md5=6bd2a53f…`, `sha256[:32]=d7431e1c…`, uuid bytes `3e6a8997…` — none match |
| **accepts itself** | ✗ feeding `31822341…` back → 403 |
| artefact already contained a flag | ✓ `session.bin`'s plaintext **is** `safctf{3e6a8997-…}` |

A genuine flag endpoint accepts its own flag; this one refuses. This is the **fourth** instance
of the pattern on this platform (Second Pressing `:8460`, Comeback Pocket `:8360`,
Northern Lights `:8370`, and here).

**Report `safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}`.**

---

## 7. Full solve script

`solve.py` — end-to-end, zero manual steps:

```python
#!/usr/bin/env python3
"""Glass Arcade (Safcom CTF) - full automated solve."""
import base64, hashlib, io, json, sys, urllib.request, zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8380"

_MASK_PAIRS = [(80,0),(188,7),(119,14),(129,21),(216,28),(120,35),(184,42),(214,49),
               (52,56),(215,63),(69,70),(26,77),(20,84),(60,91),(225,98),(175,105)]
MASK = bytes((a - b) & 0xFF for a, b in _MASK_PAIRS)
SALT = b"glass-arcade/3"

def fetch(path):
    with urllib.request.urlopen(BASE.rstrip("/") + path, timeout=60) as r:
        return r.read()

apk  = fetch("/downloads/glass-arcade.apk")
sess = json.loads(fetch("/downloads/session.json"))
zf   = zipfile.ZipFile(io.BytesIO(apk))

raw  = base64.b64decode(sess["transfer"])
seed = bytes(m ^ r for m, r in zip(MASK, raw))
key  = hashlib.sha256(seed + SALT).digest()

blob  = zf.read("assets/session.bin")
nonce, ct = blob[:12], blob[12:]
print("FLAG:", AESGCM(key).decrypt(nonce, ct, None).decode())
```

Run:

```
$ python3 solve.py
[*] target http://54.72.82.22:8380
[+] glass-arcade.apk 5309 B
[+] session.json {'account': 'cc8914d136ec62f6', 'build': 3, 'transfer': 'P9noumCVAhimnBVdDcWUyA=='}
[*] Base64.decode(transfer) = 3fd9e8ba60950218a69c155d0dc594c8
[*] seed = MASK ^ raw       = 6f6c81d6dcc08cbd5a04ea90cd24eb8e
[*] key  = SHA-256(seed || 'glass-arcade/3') = cd097113b5603025cc04b022a5bddd9cc8673e9ed4994abf1246f8b5643a9950
[*] session.bin 72 B  nonce=d9d72859b38348d224a53c79  sealed+tag=60 B
============================================================
FLAG: safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}
============================================================
```

---

## 8. Lessons / reusable technique

* **A 5 KB APK is fully readable.** No obfuscation, no libraries, one class — `strings` alone
  named every crypto primitive and the salt. Don't reach for heavy tooling before trying
  `strings | grep`.
* **`MessageDigest.digest(byte[])` means `update(input); digest()`.** The decompiled
  `md.update(seed); md.digest(salt)` is therefore `SHA-256(seed ‖ salt)`, not
  `SHA-256(salt ‖ seed)`. Order matters and only the GCM tag settles it.
* **Longhand `(A - B) ^ x` chains are a mask table, not arithmetic.** The subtraction folds to a
  constant in the bytecode; extract the difference, not the expression.
* **Split key material across files on purpose.** The APK holds the algorithm and one asset; the
  JSON holds the ciphertext and the transfer secret; the *build number* appears in both. Solving
  requires joining the two artefacts — neither is sufficient alone.
* **Unused fields in the JSON are the decoy.** `account` never appears in the dex; confirm by
  grepping the raw dex, not by assuming.
* **GCM is the oracle.** A verified tag proves the mask table, the XOR order, the concat order,
  and the build number are all right — one decrypt, no brute force.
* **The endpoint's reply is not the answer.** Fourth decoy on this platform. Verify:
  derivable? stable? self-accepting?

---

## Appendix — raw evidence captured

```
$ unzip -l glass-arcade.apk
     1528  AndroidManifest.xml
       72  assets/session.bin
     3024  classes.dex
      399  META-INF/MANIFEST.MF
     1662  META-INF/STUDIO.RSA
      604  META-INF/STUDIO.SF

$ strings -n 4 classes.dex | grep -Ev '^(L|V|I)' | head
AES/GCM/NoPadding
SHA-256 / UTF-8
Base64 / copyOfRange / digest / doFinal / getInstance / init / update
glass-arcade/3
session.bin
transfer / visit

$ cat session.json
{"account": "cc8914d136ec62f6", "build": 3, "transfer": "P9noumCVAhimnBVdDcWUyA=="}

$ python3 -c "print('account' in open('classes.dex','rb').read().decode('latin1'))"
False                      # session.json's account is a decoy

$ python3 solve.py
FLAG: safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}

POST /submit {"answer":"safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}"}
→ {"message":"safctf{318223415bd0e96e2f63b0dd88eacf2d}","ok":true}     ← DECOY
```
