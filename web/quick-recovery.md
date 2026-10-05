# Quick Recovery — CTF Writeup

**Category:** Web / Misc (OSINT-flavoured stego chain)
**Points:** 150
**Target:** `http://54.72.82.22:8010`
**Flag:** `safctf{69f779b5b18bad69606f1926395e7c2a}`

---

## 1. Challenge Description

> **Quick Recovery** — 150 pts
> *Something went wrong. Then, somehow, everything looked normal again.*
> *The system recovered quickly—but...*
> Connect to the challenge web service: `http://54.72.82.22:8010`

**Story hints interpreted:**

| Phrase | Meaning for the solve |
| --- | --- |
| "everything looked normal again" | The surface site is a decoy — nothing obviously vulnerable. |
| "recovered quickly" | **Backups / recovery copies** are involved. |
| "but..." | Something was left behind that shouldn't be public. |
| "Remember, from the root." (from the QR) | The recovered path is absolute, relative to the web root `/`. |

---

## 2. Recon

### 2.1 Fingerprint the service

```bash
curl -s -i http://54.72.82.22:8010/
```

Response headers:

```
HTTP/1.1 200 OK
Server: Apache/2.4.68 (Debian)
Last-Modified: Wed, 30 Sep 2026 12:49:27 GMT
ETag: "1738-65cb2babac3c0"
Content-Length: 5944
Content-Type: text/html
```

- **Apache 2.4.68 on Debian** — classic static-file host, so think *files and folders*, not app logic.
- The site is a themed landing page for a fictional festival called **AFTERHOURS**.

### 2.2 Read the whole landing page — do not stop at the fold

The homepage has two links (`/login.html`, `/about` — the latter 404s) and a JS widget, but the
**payoff is at the very bottom of the HTML**, in a deliberately hidden image:

```html
<script src="/js/ui.js"></script>

<img src="/assets/quick_recovery.jpg" alt="qr" style="display:none" />
```

> **Tip:** always `curl` the *full* page and grep for `img`, `src`, `href`, `display:none`,
> `hidden`, and comments. Anything rendered `display:none` is instantly suspicious.

### 2.3 The other files are noise

- `/js/ui.js` — 272 bytes, self-described:

  ```js
  // fake noisy widget values (for confusion)
  ```

  It only randomises a fake "Latency" counter. **Pure distraction.**

- `/login.html` — a form whose handler is a client-side stub:

  ```js
  function fakeLogin(e){ e.preventDefault(); alert("Sign-in was unsuccessful. Please try again."); }
  ```

  No backend, no auth. **Distraction.**

- `/assets/` — directory listing disabled (`403`), but `/assets` → `301`.

---

## 3. Step 1 — The Hidden QR Image

Download the hidden asset:

```bash
curl -o quick_recovery.jpg http://54.72.82.22:8010/assets/quick_recovery.jpg
file quick_recovery.jpg
# JPEG image data, JFIF 1.01, baseline, 3000x3000, components 3
```

A **3000×3000** image named `quick_recovery.jpg` with `alt="qr"`. It's a QR code.

### 3.1 Decode it

Install a decoder (zbar bindings + OpenCV):

```bash
pip3 install --break-system-packages pyzbar opencv-python-headless
```

Decode:

```python
import cv2
from pyzbar.pyzbar import decode

img = cv2.imread("quick_recovery.jpg")
for r in decode(img):
    print(r.data.decode())
```

> If `zbar`/`libzbar` isn't available, OpenCV alone works too:
> ```python
> cv2.QRCodeDetector().detectAndDecode(cv2.imread("quick_recovery.jpg"))[0]
> ```

**QR payload:**

```
Hey Jerry, I couldnt let the people know our secret if I was compromised.
This path should lead you to the right way, Remember, from the root.
Stay Cyber Aware and piece everything together.
/VXarjLbhJbhyqSvaqGuvf
```

---

## 4. Step 2 — ROT13 the Path

The trailing path is **ROT13** (a classic "Stay Cyber Aware" hint, and the letter distribution is a
dead giveaway — `Lbh` ↔ `You`).

```
VXarjLbhJbhyqSvaqGuvf
```

Decode with `tr`:

```bash
echo 'VXarjLbhJbhyqSvaqGuvf' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# IKnewYouWouldFindThis
```

Or in Python:

```python
import codecs; print(codecs.decode("VXarjLbhJbhyqSvaqGuvf", "rot_13"))
```

**Decoded path:** `/IKnewYouWouldFindThis`

Per the message — *"from the root"* — this is an absolute path from the web root:

```
http://54.72.82.22:8010/IKnewYouWouldFindThis
```

> **Note:** the path is **case-sensitive** (Apache on Linux). `/iknewyouwouldfindthis` will 404.

---

## 5. Step 3 — Directory Discovery ("the recovery")

Requesting the path:

```bash
curl -s -i http://54.72.82.22:8010/IKnewYouWouldFindThis
```

```
HTTP/1.1 301 Moved Permanently
Location: http://54.72.82.22:8010/IKnewYouWouldFindThis/
```

Following the redirect yields **403 Forbidden** — the directory exists but auto-indexing is off.
So we must **guess filenames**.

### 5.1 Targeted wordlist hits

```bash
B=http://54.72.82.22:8010/IKnewYouWouldFindThis
for f in index.html index.php flag flag.txt flag.php backup.zip db.sql secret.txt .htaccess; do
  printf "%-14s " "$f"
  curl -s -m 10 -o /dev/null -w "%{http_code}\n" "$B/$f"
done
```

```
index.html     404
index.php      404
flag           404
flag.txt       200   <-- hit
flag.php       200   <-- hit
backup.zip     404
db.sql         404
secret.txt     404
.htaccess      403   (exists, not readable)
```

For a wider sweep, run a directory brute-forcer against the recovered folder:

```bash
gobuster dir -u http://54.72.82.22:8010/IKnewYouWouldFindThis/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x html,php,txt,bak,zip,old,save,swp,json,db,sql -t 40
```

---

## 6. Step 4 — Retrieve the Flag

```bash
curl -s http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt
curl -s http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.php
```

Both return the same 40-byte body:

```
safctf{69f779b5b18bad69606f1926395e7c2a}
```

(The `X-Powered-By: PHP/8.2.34` header on `flag.php` is just the server-wide PHP banner — the file
serves static text, no PHP logic involved.)

### ✅ Flag

```
safctf{69f779b5b18bad69606f1926395e7c2a}
```

---

## 7. Kill Chain Summary

```
http://54.72.82.22:8010/
        │  hidden <img src="/assets/quick_recovery.jpg" style="display:none">
        ▼
/assets/quick_recovery.jpg   (3000×3000 QR code)
        │  decode
        ▼
"…Remember, from the root. /VXarjLbhJbhyqSvaqGuvf"
        │  ROT13
        ▼
/IKnewYouWouldFindThis/      (403 → dir exists, listing disabled)
        │  filename fuzz
        ▼
/IKnewYouWouldFindThis/flag.txt  →  safctf{69f779b5b18bad69606f1926395e7c2a}
```

---

## 8. Full Solve Script (copy-paste)

```bash
#!/usr/bin/env bash
# Quick Recovery — full solve
set -euo pipefail
B="http://54.72.82.22:8010"

# 1. grab the hidden QR
curl -s -o /tmp/qr.jpg "$B/assets/quick_recovery.jpg"

# 2. decode it
python3 - <<'PY'
import cv2
from pyzbar.pyzbar import decode
print(decode(cv2.imread("/tmp/qr.jpg"))[0].data.decode())
PY

# 3. ROT13 the trailing path
PATH13=$(python3 -c "import cv2;from pyzbar.pyzbar import decode;print(decode(cv2.imread('/tmp/qr.jpg'))[0].data.decode().strip().split()[-1])")
RPATH=$(echo "$PATH13" | tr 'A-Za-z' 'N-ZA-Mn-za-m')
echo "[+] recovered path: $RPATH"

# 4. pull the flag
for f in flag.txt flag.php; do
  echo "[*] $B$RPATH/$f"
  curl -s "$B$RPATH/$f"
  echo
done
```

**One-liner for the lazy:**

```bash
curl -s http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt
```

---

## 9. Tools & Techniques Used

| Tool | Purpose |
| --- | --- |
| `curl` | Header/source inspection, asset download, file discovery |
| `file`, `exiftool` | Asset identification (`JPEG 3000x3000`) |
| `pyzbar` + `opencv-python` | QR decoding (no `zbarimg` needed) |
| `tr` / Python `codecs.rot_13` | ROT13 decoding of the path |
| `gobuster` / manual `curl` loop | Directory & filename brute-force |
| HexStrike MCP | Offensive tooling orchestration |
| BlackBook MCP | Technique reference / case grounding |

### Techniques

1. **Hidden-element discovery** — inspecting the *full* HTML source (not just the rendered page)
   for `display:none` / hidden assets.
2. **QR steganography** — encoding a path inside an unobtrusive image asset.
3. **ROT13 encoding** — trivial reversible obfuscation, flagged by the "Stay Cyber Aware" hint and
   the `Lbh → You` pattern.
4. **Content discovery against a 403 directory** — a `403` on a directory confirms it exists; you
   then fuzz for filenames inside it (`200` = found).
5. **Backup-file exposure** — the whole theme ("Quick Recovery") points at leftover recovery copies
   (`flag.txt`, `flag.php`) sitting in a not-supposed-to-be-public folder.

---

## 10. Defender Takeaways

- Never ship **real secrets/backups inside the web root**, even in "hidden" folders — a `403`
  directory is enumerable, `200` files inside it are not hidden.
- `display:none` assets and comments are still **served to the client**; they are not access control.
- Encoding (ROT13/Base64) is **not** protection.
- Remove editor/backup artefacts (`*.bak`, `*.old`, `~`, `*.swp`, `.git/`) from deployments and
  disable directory listing **and** block recovery-file patterns at the server.
