# Paper Lanterns — CTF Writeup

> **Category:** OSINT · **Points:** 200 · **Difficulty:** Easy/Medium
> **Target:** `http://54.72.82.22:8480`
> **Flag:** `safctf{38309964a77c499b1ec234c401f68fe1}`

---

## 1. Challenge Brief

> *"The lanterns glow softly against the night, each one carrying a small message into the darkness. From a distance, they all look the same."*

The **"from a distance, they all look the same"** line is the thesis of the whole
challenge. It is a hint about the data you are about to receive: a set of records
that are visually/perceptually near-identical, where only one row actually
satisfies every constraint. The postcard is the "small message"; the directory is
"the darkness".

The web page frames the task explicitly:

> **Collection desk** — *Find the collection reference for the venue pictured in the field notes.*
> `field-notes.zip`

and pairs it with a submission form posting JSON `{"answer": "<ref>"}` to `/submit`.

---

## 2. Reconnaissance

### 2.1 Fingerprint the service

```bash
curl -s -i http://54.72.82.22:8480/
```

Response headers:

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 3626
```

`Werkzeug/3.1.9` over `Python/3.11.16` pins this to a **Flask** application.
Low value for exploitation (no debug pin, no `Werkzeug` console exposed), but it
tells us the backend will validate the answer server-side.

### 2.2 Page source — the interesting part

The HTML is a single static page. The relevant structural elements:

```html
<h2>Collection desk</h2>
<p>Find the collection reference for the venue pictured in the field notes.</p>
<a class="download" href="/downloads/field-notes.zip">field-notes.zip</a>

<h2>Leave a receipt</h2>
<form id="desk">
  <label for="answer">Collection receipt</label>
  <input id="answer" name="answer" autocomplete="off" required>
  <button>Send</button>
</form>
```

The inline JavaScript contains a **dead-code branch** worth noting, because it
advertises a generic request primitive the page itself never exposes:

```javascript
document.querySelector('form')?.addEventListener('submit', async e => {
  e.preventDefault();
  let out = document.getElementById('out');
  try {
    let consoleMode = e.target.id === 'console';          // <-- never true here
    let path = consoleMode
      ? document.getElementById('path').value
      : '/submit';
    if (!path.startsWith('/') || path.startsWith('//'))
      throw Error('Use a local service path.');
    let method = consoleMode ? document.getElementById('method').value : 'POST';
    let headers = consoleMode ? JSON.parse(document.getElementById('headers').value) : {};
    headers['Content-Type'] = 'application/json';
    let body = consoleMode
      ? document.getElementById('body').value
      : JSON.stringify({ answer: document.getElementById('answer').value });
    let r = await fetch(path, { method, headers, ...(method === 'GET' ? {} : { body }) });
    out.textContent = await r.text();
  } catch (e) {
    out.textContent = 'Please check the request and try again.';
  }
});
```

`e.target.id === 'console'` is dead on this page (form `id="desk"`). It is a
leftover from a shared template — a soft hint that the author builds these
challenges from a common harness. It does **not** grant anything here; the
submit path is hardcoded to `/submit`. Worth recording, not worth chasing.

### 2.3 Path probing

```bash
for p in robots.txt sitemap.xml .git/HEAD console admin api docs \
         openapi.json swagger.json downloads/ submit; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://54.72.82.22:8480/$p")
  echo "$code  /$p"
done
```

```
404  /robots.txt
404  /sitemap.xml
404  /.git/HEAD
404  /console        <-- the JS branch's target does not exist
404  /admin
404  /api
404  /docs
404  /openapi.json
404  /swagger.json
404  /downloads/
405  /submit         <-- POST-only, confirmed by Allow header
```

`/submit` returning **405** with `Allow: OPTIONS, POST` is the clean signal that
the endpoint is real and expects POST.

> Note for the record: the `console` branch is a red herring. A previous
> instinct to go hunting for an SSRF-style "fetch any local path" console is
> not what this challenge is. The flag is in the data, not the code.

---

## 3. The Field Notes

```bash
curl -s -o field-notes.zip http://54.72.82.22:8480/downloads/field-notes.zip
file field-notes.zip
# field-notes.zip: Zip archive data, made by v2.0 UNIX,
#                  last modified Fri Oct 01 03:59:42 2026, method=deflate

unzip -o field-notes.zip
#   inflating: civic-directory.json
#   inflating: postcard.txt
#   inflating: districts.csv
```

Three files. Let's read them.

### 3.1 `postcard.txt` — the clue

```
Lunch beneath a glass roof, somewhere east of the river. The brass plaque said 1997.
```

Three constraints are hidden in this one sentence:

| Prose fragment              | Constraint        | Field in directory |
| --------------------------- | ----------------- | ------------------ |
| "beneath a **glass roof**"  | glass roof        | `roof = "glass"`   |
| "**east** of the river"     | east bank         | `district = "East"`|
| "the brass **plaque said 1997**" | founding year | `opened = 1997`    |

There is no actual image, no EXIF, no geo-coordinates, no reverse-image-search
step. "Pictured in the field notes" is flavour text — the "picture" is the
postcard's prose, and the OSINT work is **joining prose to a structured record
set** rather than tracking down a real-world venue.

### 3.2 `districts.csv` — the legend

```csv
district,river_side
North,north
East,east
South,south
West,west
```

This is the **join key**. It confirms the author's vocabulary deliberately maps
"east of the river" → `district = "East"`. It is a lookup table, not a puzzle
component — but it is the artifact that tells you the postcard's geography is
meant to be read literally against the JSON's `district` column.

### 3.3 `civic-directory.json` — the haystack

36 records. The structure of every row:

```json
{
  "ref": "464d13f605",
  "name": "House 1",
  "district": "North",
  "opened": 1980,
  "roof": "copper",
  "seats": 120
}
```

The generator's fingerprint is immediately obvious when you read a few in
sequence:

- `name` increments `House 1` … `House 36`
- `district` cycles `North → East → South → West` (period 4)
- `opened` increments by exactly 1: `1980 … 2015`
- `roof` cycles `copper → slate → glass` (period 3)
- `seats` increments by exactly 11: `120 … 505`
- **`ref` is the only field that is not derivable** — 10 hex chars, looks like
  `secrets.token_hex(5)`

So four of the six columns are pure arithmetic. Only `ref` carries real
entropy, and it is the value the challenge wants. Everything else is there to
let you *address* the right row.

This is the "from a distance, they all look the same" joke: the rows are
deliberately uniform, and the clue has to be sharp enough to isolate exactly
one.

---

## 4. Solving It

### 4.1 Solve script

```python
#!/usr/bin/env python3
"""Solve Paper Lanterns: join the postcard prose to one directory row."""
import json, sys

DIRECTORY = "civic-directory.json"

# Postcard: "Lunch beneath a glass roof, somewhere east of the river.
#            The brass plaque said 1997."
CLUES = {
    "roof":     "glass",   # "beneath a glass roof"
    "district": "East",    # "east of the river"  (see districts.csv)
    "opened":   1997,      # "the brass plaque said 1997"
}

def main(path=DIRECTORY):
    rows = json.load(open(path))

    hits = [r for r in rows if all(r[k] == v for k, v in CLUES.items())]

    print(f"[*] directory rows      : {len(rows)}")
    print(f"[*] clue set            : {CLUES}")
    print(f"[*] matching rows       : {len(hits)}")
    for r in hits:
        print(f"    -> {r['name']:<9} ref={r['ref']}  "
              f"({r['district']}, {r['roof']}, {r['opened']}, {r['seats']} seats)")

    if len(hits) != 1:
        print("[!] Clue set is not discriminating — refine it.", file=sys.stderr)
        return 1

    print(f"\n[+] ANSWER: {hits[0]['ref']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

Run it:

```console
$ python3 solve.py
[*] directory rows      : 36
[*] clue set            : {'roof': 'glass', 'district': 'East', 'opened': 1997}
[*] matching rows       : 1
    -> House 18  ref=ba57ce94e3  (East, glass, 1997, 307 seats)

[+] ANSWER: ba57ce94e3
```

### 4.2 Prove the clue set is actually discriminating

A single surviving row is only meaningful if each clue *narrows*. Verification
pass:

```python
import json
d = json.load(open('civic-directory.json'))
def match(**kw):
    return [r['name'] for r in d if all(r[k] == v for k, v in kw.items())]

print("roof=glass                       ->", len(match(roof='glass')),      match(roof='glass'))
print("district=East                    ->", len(match(district='East')),   match(district='East'))
print("opened=1997                      ->", len(match(opened=1997)),       match(opened=1997))
print("district=East & roof=glass       ->", len(match(district='East', roof='glass')),
                                              match(district='East', roof='glass'))
print("East & glass & 1997              ->", len(match(district='East', roof='glass', opened=1997)),
                                              match(district='East', roof='glass', opened=1997))
```

Output:

```
roof=glass                       -> 12 ['House 3', 'House 6', 'House 9', 'House 12', 'House 15',
                                        'House 18', 'House 21', 'House 24', 'House 27', 'House 30',
                                        'House 33', 'House 36']
district=East                    -> 9  ['House 2', 'House 6', 'House 10', 'House 14', 'House 18',
                                        'House 22', 'House 26', 'House 30', 'House 34']
opened=1997                      -> 1  ['House 18']
district=East & roof=glass       -> 3  ['House 6', 'House 18', 'House 30']
East & glass & 1997              -> 1  ['House 18']
```

Interpretation:

- `roof=glass` alone is useless — it is **every 3rd row** (the period-3 cycle).
- `district=East` alone is useless — **every 4th row**.
- The conjunction `East ∧ glass` still leaves **three** candidates
  (`House 6 / 1985`, `House 18 / 1997`, `House 30 / 2009`) — **all three are
  East + glass**. This is the trap. If you only read two of the three clues you
  are left with a 1-in-3 guess and a 33% chance of a wrong submission.
- The plaque year, `opened=1997`, is the **disambiguator**. It happens to be
  unique on its own here, but its job in the puzzle is specifically to break the
  `East ∧ glass` three-way tie.

So the postcard is not three redundant clues — it is two coarse filters plus one
tie-breaker. That is the actual design of the challenge.

**Answer: `ba57ce94e3`**

---

## 5. Submission & Flag

```bash
curl -s -i -X POST http://54.72.82.22:8480/submit \
     -H 'Content-Type: application/json' \
     -d '{"answer":"ba57ce94e3"}'
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: application/json
Content-Length: 65
Connection: close

{"message":"safctf{38309964a77c499b1ec234c401f68fe1}","ok":true}
```

> ### 🚩 `safctf{38309964a77c499b1ec234c401f68fe1}`

### 5.1 Negative control (confirming the endpoint actually validates)

An empty submission is rejected — so the 200 above is a genuine pass, not a
"always returns the flag" oracle:

```bash
curl -s -i -X POST http://54.72.82.22:8480/submit \
     -H 'Content-Type: application/json' -d '{}'
```

```http
HTTP/1.1 403 FORBIDDEN
Content-Type: application/json

{"message":"The request could not be completed.","ok":false}
```

And a wrong-but-plausible ref (the `East ∧ glass` trap row, `House 6`)
likewise fails — confirming the tie-breaker clue was load-bearing:

```bash
curl -s -X POST http://54.72.82.22:8480/submit \
     -H 'Content-Type: application/json' -d '{"answer":"0ca45f3316"}'
# {"message":"The request could not be completed.","ok":false}
```

---

## 6. Flag

```
safctf{38309964a77c499b1ec234c401f68fe1}
```

---

## 7. Timeline / Command Log

| # | Action | Result |
|---|--------|--------|
| 1 | `curl -i http://54.72.82.22:8480/` | Flask/Werkzeug page, download link + `/submit` form |
| 2 | Read inline JS | Dead `console` branch; `/submit` hardcoded for this page |
| 3 | Path probe (`robots`, `.git`, `console`, `admin`, …) | All 404; `/submit` → 405 `Allow: OPTIONS, POST` |
| 4 | `curl -O /downloads/field-notes.zip` | 1295 B zip, 3 files |
| 5 | `unzip` | `civic-directory.json`, `postcard.txt`, `districts.csv` |
| 6 | Read `postcard.txt` | "glass roof" / "east of the river" / "1997" |
| 7 | Read `districts.csv` | Join key: `East` ↔ `east` |
| 8 | Parse `civic-directory.json` | 36 rows, only `ref` is non-arithmetic |
| 9 | Apply 3-clue filter | `East ∧ glass ∧ 1997` → **House 18** |
| 10 | Discriminator check | `East ∧ glass` → 3 rows; year breaks the tie |
| 11 | `POST /submit {"answer":"ba57ce94e3"}` | **200 · flag returned** |
| 12 | Negative controls (empty / trap ref) | 403 — endpoint validates properly |

---

## 8. Why This Is an "OSINT" Challenge

No exploit was used. Not a single injection, traversal, or deserialization. The
category label is the point: this is a **record-joining / entity-resolution**
exercise, which is the analytical core of real OSINT work.

The mapping to real tradecraft:

| CTF step | Real-world analogue |
|---|---|
| `postcard.txt` prose → attribute constraints | Turning a human source report into structured query terms |
| `districts.csv` → controlled vocabulary | Reconciling a source's wording against a dataset's schema |
| 36 look-alike records | Disambiguation across a registry (companies, persons, domains) |
| `East ∧ glass` → 3 candidates | Coarse filters that leave a shortlist, never an answer |
| `opened=1997` → 1 candidate | The discriminating detail that collapses a shortlist |
| `ref` as the only high-entropy field | The stable primary key you pivot on afterwards |

The BlackBook corpus frames this class of work the same way — pivoting outward
from a partial entity to a single resolvable identifier is discussed under
**OSINT Correlation Tools** in the OWASP WSTG's *Conduct Search Engine
Reconnaissance for Information Leakage* ([ref](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md)):

> "…an industry-standard OSINT and link analysis platform that maps
> relationships between domains, IP addresses, email addresses, and
> organizations through automated data transforms. Testers use it to visualize
> an organization's attack surface by **pivoting from a single entity** to
> discover related infrastructure and associated data points."

Swap "domains and IPs" for "districts and roof materials" and it is the same
operation at a much smaller scale.

---

## 9. Failure Modes Worth Recording

Things that *look* like they matter here and do not:

1. **Chasing the `console` branch.** The JS clearly contains a generic
   request-builder keyed on a form with `id="console"` — arbitrary local path,
   arbitrary method, arbitrary headers, arbitrary body. It reads like a
   hand-rolled SSRF client. It is dead code on `/submit`, `/console` is 404, and
   nothing in the challenge needs it. This is a shared-template artifact.

2. **Assuming "pictured" means there is an image.** "The venue pictured in the
   field notes" strongly implies a photo to reverse-search. There is none.
   `postcard.txt` is the "picture". Skipping a regex over the zip contents to
   look for `.jpg`/`.png` before reading the text is the mistake here.

3. **Two-clue shortcuts.** `East ∧ glass` feels decisive and gives `House 6`,
   `House 18`, `House 30`. Submitting the first hit (`House 6`) fails. The
   verification pass in §4.2 exists specifically to catch this.

4. **Treating `seats` as a clue.** It is arithmetic filler (step 11 from 120)
   and is never referenced.

---

## 10. Remediation Notes (for the challenge author / defensively)

Not applicable in the usual sense — there is no vulnerability class here worth
patching. But two observations if this template is reused for a challenge that
*does* have a live backend:

- **Remove dead template branches from served JavaScript.** The `console`
  request-builder advertises an arbitrary-path fetch primitive to every player.
  Here it is inert, but in a template where a `console` form exists elsewhere,
  it silently documents an SSRF surface and invites wasted effort. Ship only the
  branch the page uses.
- **Validate `ref` against the expected alphabet/length** before comparison
  (`^[0-9a-f]{10}$`), and compare in constant time if the value ever gates
  anything more valuable than a per-team flag. Current behaviour (403 on any
  mismatch) is already correct.

---

## 11. Reproduce in One Block

```bash
set -e
cd /tmp && mkdir -p paper-lanterns && cd paper-lanterns

curl -s -O http://54.72.82.22:8480/downloads/field-notes.zip
unzip -o field-notes.zip >/dev/null

cat postcard.txt
# Lunch beneath a glass roof, somewhere east of the river.
# The brass plaque said 1997.

REF=$(python3 -c "
import json
rows = json.load(open('civic-directory.json'))
hit  = [r for r in rows
        if r['district'] == 'East'
        and r['roof']     == 'glass'
        and r['opened']   == 1997]
assert len(hit) == 1, f'clues not discriminating: {hit}'
print(hit[0]['ref'])")

echo "ref = $REF"          # ref = ba57ce94e3
curl -s -X POST http://54.72.82.22:8480/submit \
     -H 'Content-Type: application/json' \
     -d "{\"answer\":\"$REF\"}"
# {"message":"safctf{38309964a77c499b1ec234c401f68fe1}","ok":true}
```

---

*Artifacts for this challenge live in `paper-lanterns/`: `field-notes.zip`,
`civic-directory.json`, `postcard.txt`, `districts.csv`, `solve.py`.*
