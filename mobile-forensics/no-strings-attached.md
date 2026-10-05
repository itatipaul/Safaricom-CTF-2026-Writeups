# No Strings Attached — Safcom CTF (Android / Mobile Forensics, 300 pts)

> *"A little spontaneity makes the best plans."*
>
> Hint: *An archived release note describes a recovery screen that may not exist in this build.*

| | |
|---|---|
| **Challenge** | No Strings Attached |
| **Category** | Android / Mobile forensics |
| **Points** | 300 (5 likes, 100 %) |
| **Target** | `http://54.72.82.22:8130` |
| **Artefact** | `backup.zip` (233 896 B — full Android Studio project) |
| **Decoy** | `safctf{8044-c6c9-80fd-46d5-8235-96e4-bd2c-38cc}` |
| **Flag** | `safctf{94f40cc66658c67503a859cf383c7622}` (`archive.xml` — a screen that isn't in the build) |

---

## 1. TL;DR

`backup.zip` is not an Android backup at all — it is the **entire Android Studio project** for
`com.bmacharia.safctf`, source *and* `app/build/` output. Inside there are two competing tokens, and
the challenge hint plus the build output decide which is real.

* **The decoy.** `app/src/main/res/values/archive.xml` contains
  `<string name="archive_auth_token">safctf{94f40cc6…}</string>` — the "archived release note". It is
  the only fabricated-looking file with a 2026 mtime, and it is **absent from `app/build/`** because
  the build ran years earlier: the recovery screen it belongs to *never existed in this build*. The
  hint says exactly this.
* **The flag.** `app/src/main/res/menu/main.xml` — the app's **main menu** — hides the flag as four
  `<item>` fragments with `android:title` values, deliberately shuffled, each carrying an
  `android:orderInCategory` number. The strings resource says the quiet part out loud:

  > `<string name="your_are_here_for_the_safCTF">This can be a hotel you know, check the main menu and make sure to order</string>`

  Order the four items by `orderInCategory` and concatenate their titles → the flag.

No cryptography, no SQLite, no crypto oracle this time — pure **resource forensics**. And there is
**no `/submit` endpoint at all** on this host (it is a static Apache document root), so unlike the
sibling challenges there is nothing to disambiguate against: the artefact is the only source.

---

## 2. Recon

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -sC -p 8130 54.72.82.22            # via HexStrike
8130/tcp open  http    Apache httpd 2.4.68 (Debian)
|_http-title: COMEBACK KIT

$ echo http://54.72.82.22:8130 | httpx -status-code -title -tech-detect -web-server -silent
http://54.72.82.22:8130 [200] [COMEBACK KIT] [Apache/2.4.68 (Debian)] [Apache HTTP Server:2.4.68,Debian]
```

Note the departure from the siblings: those were **Werkzeug/Flask** with a `POST /submit` JSON
checker. This one is plain **Apache 2.4.68** — the tell that there is no application logic here,
only static files.

### 2.2 Landing page

```html
<header class="scene-masthead">…COMEBACK KIT…K-pop mobile app</header>
<section class="scene-hero">…New outfits. New choreography. A chorus made for the whole crowd.</section>

<h4>Your backstage download</h4>
<p>The rehearsal room is buzzing. The countdown has officially begun.</p>
<p><a href="/backup.zip">Download the comeback kit</a></p>
```

One download link, no forms, no inline JS, no fetches.

### 2.3 Endpoint surface

Probed to be sure there is no hidden checker:

| path | GET | POST |
|---|---|---|
| `/`, `/index.html` | 200 (5 063 B) | — |
| `/backup.zip` | 200 (233 896 B) | — |
| `/submit` | **404** | **404** |
| `/downloads/`, `/robots.txt`, `/flag` | 404 | — |

**There is no `/submit` on :8130.** Nothing to compare a candidate against — so the flag must be
derived purely from the artefact, and the decoy must be eliminated by reasoning, not by asking the
server.

---

## 3. The artefact

```
$ file backup.zip
Zip archive data, made by v2.0 UNIX, extract using at least v2.0,
last modified May 22 2025 22:33:38, uncompressed size 0, method=store

$ unzip -l backup.zip | tail -3
---------                     -------
   375953                     278 files
```

278 entries: a complete Gradle/Android Studio project (`gradlew`, `settings.gradle`,
`local.properties`, `.idea/`, `.gradle/` caches, `app/build/intermediates/…`) plus macOS litter
(`.DS_Store`, `__MACOSX/` AppleDouble sidecars). The presence of `app/build/` is the gift — it lets
us compare **source** against **what actually got compiled**.

The `README` is the first nudge:

```
### Let's get mobile!
When she said that she doesn't want any strings attached, did she mean it?
We can tell you for sure it was a big fat lie. We all have strings attached!
```

*"strings attached"* → Android **string resources**. That is the category of file to hunt in.

---

## 4. Two candidate tokens

Grep the whole tree for the flag shape:

```
$ grep -rlao 'safctf{' x | sort
x/safctfapp/app/src/main/res/menu/main.xml
x/safctfapp/app/src/main/res/values/archive.xml
```

Exactly two files. Everything else is boilerplate.

### 4.1 `values/archive.xml` — the archived release note (DECOY)

```xml
<resources><string name="archive_auth_token">safctf{94f40cc66658c67503a859cf383c7622}</string></resources>
```

A single, complete, plausible-looking flag. This is the trap, and three independent facts expose it:

**(a) Nothing in the project references it.** No Kotlin, no layout, no other resource mentions
`archive_auth_token` or `archive`:

```
$ grep -rn 'archive_auth_token\|archive' x --include=*.kt --include=*.java --include=*.xml …
(no references at all)
```

**(b) It is not in the build output.** The project ships its `app/build/` tree, so we can see exactly
which resources were compiled. `archive_auth_token` is simply not there:

```
$ grep -c 'archive_auth_token' app/build/intermediates/packaged_res/debug/values/values.xml
0
```

**(c) Its mtime is years adrift.** Compare:

```
2023-08-31 13:02:33   app/src/main/res/menu/main.xml            ← built into the app
2023-08-31 12:26:50   app/src/main/res/values/strings.xml       ← built into the app
2026-09-28 23:49:30   app/src/main/res/values/archive.xml       ← NOT in the build
```

The project was built on 2023-08-31. `archive.xml` was dropped in on **2026-09-28**, roughly three
years later — long after the last compile, and days before this challenge was published. It is an
*archived* note: a description of a recovery screen that, exactly as the hint warns, **does not
exist in this build**. Report it and you report a ghost.

### 4.2 `menu/main.xml` — the app's main menu (FLAG)

```xml
<?xml version="1.0" encoding="utf-8"?>
<menu xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto">
    <item
        android:id="@+id/action_settings"
        android:orderInCategory="100"
        android:title="@string/action_settings"
        android:showAsAction="never" />
    <item android:id="@+id/safctf1"
        android:orderInCategory="104"
        android:title="safctf{8044-c6c9-"
        android:showAsAction="never" />
    <item android:id="@+id/safctf2"
        android:orderInCategory="137"
        android:title="bd2c-38cc}"
        android:showAsAction="never" />
    <item android:id="@+id/safctf3"
        android:orderInCategory="111"
        android:title="80fd-46d5-"
        android:showAsAction="never" />
    <item android:id="@+id/safctf4"
        android:orderInCategory="121"
        android:title="8235-96e4-"
        android:showAsAction="never" />
</menu>
```

Four items, ids `safctf1..4`, titles that are bare flag fragments — an opening brace on one, a
closing brace on another, and the file is **shuffled**: the closing-brace fragment (`safctf2`,
`orderInCategory=137`) appears *second* in file order. `android:orderInCategory` is the real
ordering key. And critically, this file **did** make the build:

```
$ cat app/build/intermediates/packaged_res/debug/menu/main.xml
… identical, fragments and all …
```

### 4.3 The hint that ties it together

`values/strings.xml` carries one string that is not template boilerplate — and it is in the built
`values.xml` too, so it is genuinely part of this build:

```xml
<string name="your_are_here_for_the_safCTF">This can be a hotel you know, check the main menu and make sure to order</string>
```

> *"check the **main menu** and make sure to **order**"* — check `res/menu/main.xml`, and order it.

Nothing here is subtle once the metaphor is unstuck: **strings attached** = the flag is carried by
Android *string-ish* resources; **main menu** = `res/menu/main.xml`; **order** = sort by
`orderInCategory`.

---

## 5. Reassembly

Sort the four `safctf*` items ascending by `android:orderInCategory` and concatenate the titles:

| # | id | `orderInCategory` | `android:title` |
|---|---|---|---|
| 1 | `safctf1` | **104** | `safctf{8044-c6c9-` |
| 2 | `safctf3` | **111** | `80fd-46d5-` |
| 3 | `safctf4` | **121** | `8235-96e4-` |
| 4 | `safctf2` | **137** | `bd2c-38cc}` |

```
safctf{8044-c6c9- + 80fd-46d5- + 8235-96e4- + bd2c-38cc}
= safctf{8044-c6c9-80fd-46d5-8235-96e4-bd2c-38cc}
```

Sanity check the payload is a real identifier, not a scrambled string:

```
$ python3 -c "import uuid; u=uuid.UUID('8044c6c9-80fd-46d5-8235-96e4bd2c38cc'); print(u, u.version, u.variant)"
8044c6c9-80fd-46d5-8235-96e4bd2c38cc 4 specified in RFC 4122
```

A well-formed **UUID v4** (`46d5` → version 4 nibble; `8235` → RFC 4122 variant). The ordering is
correct — a wrong permutation would not produce a valid v4 UUID. This is the internal consistency
check that replaces the missing `/submit` oracle.

The decoy, by contrast, is 32 bare hex characters with no dashes — not the UUID shape every other
Safcom flag on this platform uses:

```
safctf{94f40cc66658c67503a859cf383c7622}     ← 32 hex, no dashes ≠ UUID shape
```

---

## 6. Why the decoy loses — consolidated

| test | `archive.xml` token | `menu/main.xml` token |
|---|---|---|
| referenced by any code | ✗ none | ✗ (menu ids are also unreferenced — UI-only, expected) |
| present in the **build output** | ✗ **absent** — proves the screen doesn't exist | ✓ in `packaged_res/debug/menu/main.xml` |
| mtime consistent with the build | ✗ 2026-09-28 vs a 2023-08-31 build | ✓ 2023-08-31 13:02 |
| matches the platform flag shape (UUID v4) | ✗ 32 bare hex | ✓ valid UUID v4 |
| corroborated by an in-build hint | ✗ | ✓ "check the main menu and make sure to order" |

`archive.xml` is *designed* to be found — it is named after the hint, it holds a complete
brace-balanced flag, and it is easy to stop there. The build output is what convicts it: a resource
that was never compiled cannot be part of "this build".

**Report `safctf{8044-c6c9-80fd-46d5-8235-96e4-bd2c-38cc}`.**

---

## 7. Attack-chain summary

```
GET / ─────────────► static Apache landing page ("COMEBACK KIT")
   │                     single link, no forms, no JS, **no /submit**
   │
   └─ GET /backup.zip ─► 233 896 B ZIP = full Android Studio project
          │                 (safctfapp/ … 278 entries, incl. app/build/)
          │
          ├─ README ............... "We all have strings attached!"  → look at string resources
          │
          ├─ res/values/archive.xml ....... safctf{94f40cc6…}
          │        └─ mtime 2026-09-28, NOT in app/build/  → archived note for a
          │           recovery screen that does not exist  →  DECOY
          │
          ├─ res/values/strings.xml ....... "check the main menu and make sure to order"
          │
          └─ res/menu/main.xml ............ 4 shuffled fragment items
                   │   safctf1 order=104  "safctf{8044-c6c9-"
                   │   safctf2 order=137  "bd2c-38cc}"
                   │   safctf3 order=111  "80fd-46d5-"
                   │   safctf4 order=121  "8235-96e4-"
                   ▼
        sort by android:orderInCategory, concatenate android:title
                   ▼
        safctf{8044-c6c9-80fd-46d5-8235-96e4-bd2c-38cc}   ← FLAG  (valid UUID v4)
```

---

## 8. Full solve script

`solve.py` — end-to-end, no manual steps:

```python
#!/usr/bin/env python3
"""No Strings Attached (Safcom CTF) - full automated solve."""
import io, re, sys, urllib.request, zipfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8130"

def fetch(path):
    with urllib.request.urlopen(BASE.rstrip("/") + path, timeout=60) as r:
        return r.read()

zp = fetch("/backup.zip")
zf = zipfile.ZipFile(io.BytesIO(zp))

# the decoy: an "archived" release note for a screen that is not in this build
arch  = zf.read("safctfapp/app/src/main/res/values/archive.xml").decode()
decoy = re.search(r'archive_auth_token">([^<]+)<', arch).group(1)
print(f"[!] archive.xml -> {decoy}   <- DECOY (never compiled into app/build/)")

# the in-build hint
strings = zf.read("safctfapp/app/src/main/res/values/strings.xml").decode()
print("[*] hint:", re.search(r'your_are_here_for_the_safCTF">([^<]+)<', strings).group(1))

# the main menu, ordered by android:orderInCategory
menu  = zf.read("safctfapp/app/src/main/res/menu/main.xml").decode()
items = re.findall(r'<item\s+android:id="@\+id/safctf\d+"\s+'
                   r'android:orderInCategory="(\d+)"\s+'
                   r'android:title="([^"]+)"', menu)
flag  = "".join(t for _, t in sorted(items, key=lambda x: int(x[0])))
print("FLAG:", flag)
```

Run:

```
$ python3 solve.py
[*] target http://54.72.82.22:8130
[+] backup.zip 233896 B
[!] archive.xml (archived release note) -> safctf{94f40cc66658c67503a859cf383c7622}   <- DECOY
    hint: 'a recovery screen that may not exist in this build'
[*] strings.xml hint: This can be a hotel you know, check the main menu and make sure to order
    orderInCategory=104  safctf{8044-c6c9-
    orderInCategory=111  80fd-46d5-
    orderInCategory=121  8235-96e4-
    orderInCategory=137  bd2c-38cc}
============================================================
FLAG: safctf{8044-c6c9-80fd-46d5-8235-96e4-bd2c-38cc}
============================================================
```

---

## 9. Lessons / reusable technique

* **Ship the build directory, hand over the ground truth.** When an artefact includes compiled
  output (`app/build/intermediates/`), every "is this real?" question becomes mechanical: does the
  resource exist in `packaged_res/`? Here that single check separated a decoy (`archive.xml`,
  never compiled) from the flag (`menu/main.xml`, compiled).
* **Timestamps are evidence.** A 2026-09-28 source file inside a project last built 2023-08-31 is
  shouting. `find -printf '%TY-%Tm-%Td %TH:%TM %p'` over a tree, sorted, reconstructs the author's
  edit order and instantly flags the planted file.
* **"A screen that may not exist in this build" is a literal instruction, not flavour text.** Verify
  it: grep for references, check the compiled resources, compare mtimes. The hint told us the decoy
  was a decoy.
* **Follow the flavour text into the right resource class.** *"We all have strings attached"* →
  string resources; *"check the main menu and make sure to order"* → `res/menu/main.xml`, sorted.
  CTF prose is usually a map legend.
* **`android:orderInCategory` beats file order.** The fragments were deliberately shuffled in the
  XML; the ordering attribute is the only correct key. Guessing permutations is avoidable — and the
  resulting value's own shape confirms the order.
* **Use the flag's own format as an oracle when there is no `/submit`.** This host has no answer
  checker, but the concatenation must parse as a **UUID v4** to be right. A wrong permutation fails
  that check for free.
* **Do not stop at the first brace-balanced flag.** `archive.xml` was engineered to be found first.
  On this platform, "shape-valid, stable, self-accepting" is not enough — the decisive test here was
  **provenance**: was the token ever part of the build?

---

## Appendix — raw evidence captured

```
$ file backup.zip
Zip archive data, made by v2.0 UNIX, extract using at least v2.0,
last modified May 22 2025 22:33:38, uncompressed size 0, method=store

$ grep -rlao 'safctf{' x | sort
x/safctfapp/app/src/main/res/menu/main.xml
x/safctfapp/app/src/main/res/values/archive.xml

$ grep -rn 'archive_auth_token\|archive' x --include=*.kt --include=*.java --include=*.xml
(no references at all)

$ grep -c 'archive_auth_token' \
      x/safctfapp/app/build/intermediates/packaged_res/debug/values/values.xml
0

$ grep -o 'hotel[^<]*' \
      x/safctfapp/app/build/intermediates/packaged_res/debug/values/values.xml
hotel you know, check the main menu and make sure to order

$ cat x/safctfapp/app/build/intermediates/packaged_res/debug/menu/main.xml
<safctf fragments present in the built resources>

$ python3 -c "import uuid;u=uuid.UUID('8044c6c9-80fd-46d5-8235-96e4bd2c38cc');print(u,u.version)"
8044c6c9-80fd-46d5-8235-96e4bd2c38cc 4
```
