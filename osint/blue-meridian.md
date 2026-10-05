# Blue Meridian — CTF Writeup

> **Category:** OSINT · **Points:** 550 · **Difficulty:** Hard
> **Target:** `http://54.72.82.22:8500`
> **Flag:** `safctf{756f7d81426571a6d6dac9b1aae5f271}`

---

## 1. Challenge Brief

> *"The map looks different after midnight. A single line cuts quietly across the familiar landscape, pointing toward somewhere that isn't marked on any ordinary chart. The route is there. The destination is not."*

The page states the task plainly:

> **Collection desk** — *Identify the documented departure and return its collection receipt.*

**"Identify the documented departure"** — one specific voyage out of sixty. This is the
550-point ceiling of the series, and the step up from **Last Tram Home** (300 pts) is
structural: where that challenge joined on *two* keys and converted one timezone, this one
joins on five attributes and the first key you reach for returns **two** candidates.

---

## 2. Reconnaissance

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8500/
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Date: Fri, 02 Oct 2026 08:17:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3611
Connection: close
```

Flask / Werkzeug 3.1.9 on Python 3.11.16 — the same stack as every other service on this
host.

### 2.2 Path probe

```bash
for p in robots.txt sitemap.xml .git/HEAD flag flag.txt admin api docs \
         openapi.json swagger.json submit health status debug console \
         static/ downloads/ voyage voyages station stations tide receipt; do
  printf "%-16s %s\n" "/$p" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://54.72.82.22:8500/$p")"
done
```

```
/robots.txt      404     /health          200
/sitemap.xml     404     /status          404
/.git/HEAD       404     /debug           404
/flag            404     /console         404
/flag.txt        404     /static/         404
/admin           404     /downloads/      404
/api             404     /voyage          404
/docs            404     /voyages         404
/openapi.json    404     /station         404
/swagger.json    404     /stations        404
/submit          405     /tide            404
                         /receipt         404
```

- `/submit` → **405** with `Allow: OPTIONS, POST` — the real endpoint.
- `/health` → **200** `{"status":"ok"}` — boilerplate liveness, no data.
- The four resource words the challenge itself uses (`voyage`, `station`, `tide`,
  `receipt`) are all 404 at the HTTP layer. Everything is in the zip.

### 2.3 The template, third iteration

The served HTML is the same generator output as Paper Lanterns and Last Tram Home:

- same two-card `Collection desk` / `Leave a receipt` grid,
- same `<form id="desk">`,
- same `POST /submit` JSON `{"answer": "..."}` contract,
- same **dead `consoleMode` branch**:

```javascript
let consoleMode = e.target.id === 'console';                 // form is id="desk" -> false
let path  = consoleMode ? document.getElementById('path').value : '/submit';
let method= consoleMode ? document.getElementById('method').value : 'POST';
let body  = consoleMode ? document.getElementById('body').value
                        : JSON.stringify({answer: document.getElementById('answer').value});
```

`consoleMode` can never be true, `/console` 404s, and the branch is an inert template
artifact advertising a generic request primitive. Third sighting; verified once and
discarded.

> **Standing lesson for this host:** these challenges share one generator. The web layer is
> a fixed shell and *all* difficulty lives in the downloadable dataset. Time spent on the
> HTTP surface is wasted.

---

## 3. The Field Notes

```bash
mkdir -p blue-meridian && cd blue-meridian
curl -s -O http://54.72.82.22:8500/downloads/field-notes.zip
unzip -l field-notes.zip
```

```
  Length      Date    Time    Name
---------  ---------- -----   ----
     5063  2026-10-01 03:59   civic-directory.json
     7387  2026-10-01 03:59   voyages.json
      912  2026-10-01 03:59   tide-station.csv
      111  2026-10-01 03:59   camera-metadata.json
       94  2026-10-01 03:59   pier-note.txt
       94  2026-10-01 03:59   submission.txt
---------                     -------
    13661                     6 files
```

Six files — the largest set in the series. Two are prose/contract, one is structured
metadata, two are datasets, and one is a decoy.

### 3.1 `submission.txt` — the contract

```
Receipt format: SHA256(voyage_ref|station_ref|UTC_time), lowercase hex. UTC_time uses HH:MMZ.
```

Three inputs, pipe-separated, SHA-256, lowercase hex. Two details matter:

- The third input is **`UTC_time`**, explicitly formatted **`HH:MMZ`** — an *hour* and
  *minute*, not a date. The earlier challenge in this series hashed a date; here you must
  read the format string rather than pattern-match the previous solution.
- The second input is **`station_ref`**, not the station's `tide_cm`. The receipt wants the
  *identifier*, and it sits in the middle of the preimage.

### 3.2 `pier-note.txt` — the clue

```
At the exposure, the gauge was 219 cm. Clock and compass had both been serviced that morning.
```

Two sentences, and the second is the interesting one. It reads as scene-setting; it is
actually a **trust assertion**. "Serviced that morning" means the instruments were
calibrated — so the clock reading is true (no drift to correct) and the compass reading is
true (no deviation to apply). The note is telling you *not* to second-guess the metadata you
are about to be handed. It is the inverse of Last Tram Home's timezone hint: same hint
slot, opposite instruction — there you had to correct the time, here you must not.

### 3.3 `camera-metadata.json` — four attributes

```json
{"local_time": "2026-06-04T21:00:00", "utc_offset": "+02:00",
 "compass_degrees": 11, "vessel_mark": "vessel-3"}
```

Four usable values. One needs conversion; three are direct join keys:

| Field | Role |
|---|---|
| `local_time` + `utc_offset` | must be **converted** to UTC → `19:00Z` |
| `compass_degrees: 11` | direct → voyage `bearing` |
| `vessel_mark: "vessel-3"` | direct → voyage `vessel` |

### 3.4 `tide-station.csv` — gauge → station

```csv
station,tide_cm
c04ea84e75,90
a462e36ed6,93
d8fde1a134,96
...
b4fc68cb9f,267
```

60 rows, **36 distinct stations**. Tide rises from 90 to 267 in steps of 3.

### 3.5 `voyages.json` — the target records

60 entries:

```json
{
  "ref": "5ea9e4e9a0df442e",
  "vessel": "vessel-0",
  "station": "c04ea84e75",
  "utc_hour": 0,
  "tide_cm": 90,
  "bearing": 0
}
```

### 3.6 `civic-directory.json` — the decoy

```json
{"ref": "c04ea84e75", "name": "House 1", "district": "North",
 "opened": 1980, "roof": "copper", "seats": 120}
```

Same `ref`/`name`/`district`/`opened`/`roof`/`seats` schema as Paper Lanterns. Its 36 refs
are **exactly the 36 distinct station refs**:

```python
set(r['ref'] for r in civic) == set(r['station'] for r in tide)   # -> True
```

So it is a directory keyed by *station*, dressed in the sibling challenge's schema. Its
`name`, `district`, `opened`, `roof`, and `seats` fields are never referenced by any clue.
The receipt needs the **16-hex `voyage_ref`**, and this file offers only 10-hex **station**
refs — so its real hazard is mild but real: it invites you to submit a station ref where a
voyage ref belongs. Note the contrast with Last Tram Home, where the decoy was byte-identical
to the working table; here the generator has at least rotated which key it mirrors.

---

## 4. Dataset Forensics — Reading the Generator

Before solving, spend two minutes on the structure of `voyages.json`. It is entirely
mechanical. For row index `i` (0-based):

| Field | Generator | Verified |
|---|---|---|
| `station` | cycles with period 36 | ✅ 60/60 |
| `tide_cm` | `90 + 3i` | ✅ 60/60 |
| `utc_hour` | `i % 24` | ✅ 60/60 |
| `bearing` | `(17i) % 360` | ✅ 60/60 |
| `vessel` | `vessel-(i % 8)` | ✅ 60/60 |
| `ref` | 16 hex chars, unique | ✅ 60/60 |

```console
=== generator structure ===
  OK  station period36
  OK  tide=90+3i
  OK  hour=i%24
  OK  bearing=(17i)%360
  OK  vessel=vessel-(i%8)
  OK  ref 16 hex
```

This is worth doing because it tells you **which attributes are actually independent
evidence**. `tide_cm`, `utc_hour`, `bearing`, and `vessel` are all deterministic functions
of `i`, but they are *different* functions — so agreement across all four is not
corroboration of one underlying fact, it is a convergence on a single row index. That is
precisely what makes the join safe.

It also tells you the trap. `tide_cm = 90 + 3i` means the tide value alone pins `i`
uniquely (219 → `i = 43`). And `station` has only period 36 across 60 rows, so **24 of the
36 stations appear twice**. Concretely:

```console
=== discriminator analysis ===
station alone (from tide table)          -> 2 candidates
station + tide_cm=219                    -> 1 candidate
tide_cm=219 alone (index=(219-90)/3=43)  -> 1 candidate
```

The station is the *natural* first key — it is the field shared verbatim between the two
files — and it is the one that leaves you with a coin flip.

---

## 5. Solving It — The Reconciliation

```
pier-note.txt          tide-station.csv              camera-metadata.json
  gauge 219 cm  ─────▶  station 5255073ff2  ─┐
                                             │       21:00 +02:00 ─▶ 19:00Z
                                             │       compass 11, vessel-3
                                             ▼
                                        voyages.json
                              station + tide + hour + bearing + vessel
                                             │
                                             ▼
                                    voyage d0b36031a079e290
                                             │
submission.txt ─▶ SHA256(voyage_ref|station_ref|UTC_time) ─▶ receipt
```

### 5.1 Step 1 — gauge → station

`pier-note.txt` gives `219 cm`. Look it up in `tide-station.csv`:

```console
[1] gauge 219 cm -> station_ref(s): ['5255073ff2']
```

Exactly one station. Note this step is *nearly* free — the tide table's `tide_cm` column is
a unique key, so the gauge reading identifies the station directly. The interesting part is
that it does **not** identify the voyage, which is the next step's problem.

### 5.2 Step 2 — local time → UTC

`camera-metadata.json` records `2026-06-04T21:00:00` with offset `+02:00`. Converting:

```
21:00 (local, UTC+2)  −  2h  =  19:00 UTC, same calendar day  →  UTC_time = 19:00Z
```

Rollover is handled properly in `solve.py` (the hour is carried as minutes-since-midnight
and re-divided, so the day shifts correctly in either direction). The formula asks only for
`HH:MMZ`, so the date does not enter the preimage — but a naive implementation that only
subtracts from the hour *field* would still be wrong on a negative-offset input, and the
discipline is worth keeping.

The other two attributes are used as-is, on the pier note's assurance that the instruments
were serviced: `bearing = 11`, `vessel = vessel-3`.

### 5.3 Step 3 — the five-attribute join

Filter `voyages.json` to the station, then score every candidate against all four remaining
attributes:

```console
[3] voyages sharing that station: 2
      0ca1db63cdff56d7 vessel=vessel-7  hour= 7 tide=111 bearing=119  (only 0/4)
      d0b36031a079e290 vessel=vessel-3  hour=19 tide=219 bearing= 11  <== FULL MATCH (4/4)
```

**This is the challenge.** Two voyages share station `5255073ff2`, and they are maximally
separated — different vessel, different hour, different tide, different bearing. The decoy
scores **0 out of 4**. There is no partial credit and no near-miss to argue about.

The join is therefore unambiguous, and it is unambiguous *by construction*: the generator
placed the two rows 36 apart in the index (7 and 43), which is exactly the station period,
so they share only the station and nothing else.

Corroboration across four independent generators is what converts a 50/50 guess into a
certainty. Had the two candidates differed in only one attribute, you would be guessing;
because they differ in all four, the single surviving row is the answer with overwhelming
confidence.

### 5.4 Step 4 — the receipt

```
preimage = "d0b36031a079e290|5255073ff2|19:00Z"
receipt  = SHA256(preimage)
         = a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845
```

### 5.5 Solver

`solve.py` (full source in the artifacts directory):

```python
#!/usr/bin/env python3
"""Solve Blue Meridian."""
import csv, hashlib, json

GAUGE_CM = 219
ATTRS = ("tide_cm", "utc_hour", "bearing", "vessel")

def to_utc(local_iso, offset):
    """ISO local time + '+HH:MM'/'-HH:MM' -> (HH:MMZ, full ISO). UTC = local - offset."""
    sign = 1 if offset[0] == "+" else -1
    oh, om = (int(x) for x in offset[1:].split(":"))
    off_min = sign * (oh * 60 + om)

    date_part, time_part = local_iso.split("T")
    y, mo, d = (int(x) for x in date_part.split("-"))
    hh, mm, ss = (int(x) for x in time_part.split(":"))

    total = hh * 60 + mm - off_min
    day_shift, rem = divmod(total, 1440)
    hh, mm = divmod(rem, 60)
    d += day_shift
    iso_date = f"{y:04d}-{mo:02d}-{d:02d}"
    return f"{hh:02d}:{mm:02d}Z", f"{iso_date}T{hh:02d}:{mm:02d}:{ss:02d}Z"

def main():
    voyages = json.load(open("voyages.json"))
    tide    = list(csv.DictReader(open("tide-station.csv")))
    camera  = json.load(open("camera-metadata.json"))
    civic   = json.load(open("civic-directory.json"))

    print(f"[*] civic rows : {len(civic)}  refs == station refs ? "
          f"{set(r['ref'] for r in civic) == {r['station'] for r in tide}}")

    stations = {r["station"] for r in tide if int(r["tide_cm"]) == GAUGE_CM}
    print(f"[1] gauge {GAUGE_CM} cm -> {sorted(stations)}")

    utc_hhmm, utc_iso = to_utc(camera["local_time"], camera["utc_offset"])
    print(f"[2] {camera['local_time']} at {camera['utc_offset']} -> {utc_iso} "
          f"-> UTC_time = {utc_hhmm}")

    expected = {"tide_cm": GAUGE_CM, "utc_hour": int(utc_hhmm[:2]),
                "bearing": camera["compass_degrees"], "vessel": camera["vessel_mark"]}

    pool = [v for v in voyages if v["station"] in stations]
    hits = []
    for v in pool:
        score = sum(v[k] == expected[k] for k in ATTRS)
        flag = f"  <== FULL MATCH ({score}/{len(ATTRS)})" if score == len(ATTRS) \
               else f"  (only {score}/{len(ATTRS)})"
        print(f"      {v['ref']} vessel={v['vessel']:<9} hour={v['utc_hour']:>2} "
              f"tide={v['tide_cm']:>3} bearing={v['bearing']:>3}{flag}")
        if score == len(ATTRS):
            hits.append(v)
    assert len(hits) == 1, hits

    voyage_ref, station_ref = hits[0]["ref"], hits[0]["station"]
    preimage = f"{voyage_ref}|{station_ref}|{utc_hhmm}"
    print(f"\n[4] preimage : {preimage}")
    print(f"[+] RECEIPT  : {hashlib.sha256(preimage.encode()).hexdigest()}")

if __name__ == "__main__":
    main()
```

Output:

```console
$ python3 solve.py
[*] voyages          : 60  keys ['ref', 'vessel', 'station', 'utc_hour', 'tide_cm', 'bearing']
[*] tide rows        : 60  (36 distinct stations)
[*] civic rows       : 36  refs == station refs ? True   <- civic-directory is keyed by station, adds nothing

[1] gauge 219 cm -> station_ref(s): ['5255073ff2']
[2] 2026-06-04T21:00:00 at +02:00 -> 2026-06-04T19:00:00Z  -> UTC_time = 19:00Z
    compass 11 deg, vessel-3
[3] voyages sharing that station: 2
      0ca1db63cdff56d7 vessel=vessel-7  hour= 7 tide=111 bearing=119  (only 0/4)
      d0b36031a079e290 vessel=vessel-3  hour=19 tide=219 bearing= 11  <== FULL MATCH (4/4)
[3] voyage_ref = d0b36031a079e290

[4] preimage : d0b36031a079e290|5255073ff2|19:00Z
[+] RECEIPT  : a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845
```

---

## 6. Submission & Flag

```bash
curl -s -i -X POST http://54.72.82.22:8500/submit \
     -H 'Content-Type: application/json' \
     -d '{"answer":"a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845"}'
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: application/json
Content-Length: 65

{"message":"safctf{756f7d81426571a6d6dac9b1aae5f271}","ok":true}
```

> ### 🚩 `safctf{756f7d81426571a6d6dac9b1aae5f271}`

### 6.1 Negative controls

Four variants, each changing exactly one load-bearing decision, all rejected with
`403 {"message":"The request could not be completed.","ok":false}`:

| Variant | Result |
|---|---|
| **correct receipt** | ✅ 200 — flag |
| decoy `voyage_ref` (same station, 0/4 match) | ❌ 403 |
| local time passed through unconverted (`21:00Z`) | ❌ 403 |
| wrong offset sign (`17:00Z`) | ❌ 403 |
| empty answer | ❌ 403 |

The decoy control is the one that matters most: it is the receipt you get by stopping at
the station-level join and guessing the wrong branch of the coin flip, and it fails. The
timezone controls confirm the conversion is load-bearing rather than incidental. There is
no oracle — the endpoint validates the full preimage.

---

## 7. Timeline / Command Log

| # | Action | Result |
|---|--------|--------|
| 1 | `curl -i http://54.72.82.22:8500/` | Flask page; `field-notes.zip` + `/submit` |
| 2 | Read inline JS | Third sighting of the template; dead `console` branch |
| 3 | Path probe (24 paths) | All 404; `/submit` 405; `/health` 200 (no data) |
| 4 | `curl -O /downloads/field-notes.zip` | 3857 B, 6 files |
| 5 | `unzip` | `voyages.json`, `tide-station.csv`, `camera-metadata.json`, `pier-note.txt`, `submission.txt`, `civic-directory.json` |
| 6 | Read `submission.txt` | `SHA256(voyage_ref\|station_ref\|UTC_time)`, `HH:MMZ` |
| 7 | Read `pier-note.txt` | gauge 219 cm; instruments serviced → trust the metadata |
| 8 | `tide-station.csv` lookup | 219 cm → station `5255073ff2` (unique) |
| 9 | Timezone conversion | `21:00 +02:00` → `19:00Z` |
| 10 | Generator inference | station p36, tide `90+3i`, hour `i%24`, bearing `(17i)%360`, vessel `i%8` |
| 11 | Station join | **2 candidates** — the trap |
| 12 | 4-attribute score | decoy 0/4, answer 4/4 → `d0b36031a079e290` |
| 13 | SHA-256 the preimage | receipt `a037d4fd…962c845` |
| 14 | `POST /submit` | **200 · flag returned** |
| 15 | 4 negative controls | all 403 — endpoint validates properly |

---

## 8. Why This Is an "OSINT" Challenge

Nothing was exploited. The challenge is **multi-source entity resolution** with a
deliberately ambiguous first key, which is exactly the shape of real intelligence
correlation: you have a partial observation from one source, a reference table, and a
metadata record, and you must converge on one entity out of many plausible ones.

| CTF step | Real-world analogue |
|---|---|
| `pier-note.txt` prose | A human source report; the second sentence is a *reliability caveat* |
| "clock and compass had both been serviced" | Source-confidence annotation — telling the analyst the instrument readings are trustworthy |
| `tide-station.csv` | A reference table mapping an observed measurement to an identifier |
| station join returning 2 rows | The classic false-positive pair — one shared key, no other agreement |
| scoring 4 independent attributes | Multi-attribute corroboration before asserting an identification |
| `camera-metadata.json` | Device/EXIF metadata recovered alongside a collection |
| `civic-directory.json` | A neighbouring dataset keyed on a *different* identifier, easy to reach for by mistake |
| the receipt `SHA256(a\|b\|c)` | A commitment to a specific chain of reasoning — one wrong link and it silently fails |

The BlackBook corpus frames the general discipline directly. OWASP WSTG, *Conduct Search
Engine Reconnaissance for Information Leakage*, § **OSINT Correlation Tools**
([ref](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md)):

> "Beyond individual search engines, testers can use dedicated OSINT frameworks to
> **correlate and visualize relationships** between discovered entities."

and the practitioner view from 0xdf, *Pivoting off Phishing Domain*
([ref](https://0xdf.gitlab.io/2021/08/27/pivoting-off-phishing-domain.html)):

> "The power comes in the **transforms**. They connect to different data source APIs and
> **make connections for you**."

That is exactly the mental model this challenge rewards. A "transform" is a join, and the
analyst's job is to know which transforms return one row and which return a set — and to
refuse to assert an identity while the set still has two members.

The single most transferable lesson here is the **ambiguous key**. `station` is the field
that looks most joinable — it is the only value shared verbatim between `tide-station.csv`
and `voyages.json` — and it is the one that returns a pair. The attributes that actually
discriminate came from a *different* source (the camera metadata) entirely. Correlation is
not "find the shared column"; it is "find enough independent agreement that only one row
survives."

---

## 9. Failure Modes Worth Recording

1. **Stopping at the station join.** The natural chain is `gauge → station → voyage`, and
   it returns two rows. Twenty-four of the thirty-six stations are duplicated in the tide
   table, so this is not a one-off; it is the designed trap. If you submit either candidate
   without checking the other, you have a 50% chance and no way to know which half you got.

2. **Ignoring the second sentence of the pier note.** "Clock and compass had both been
   serviced that morning" is easy to read as flavour text. It is an instruction: *trust
   these readings as recorded.* An analyst who instead "corrects" the compass for deviation
   or the clock for drift invents a value that matches nothing.

3. **Reusing Last Tram Home's receipt shape.** That challenge hashed a **date**
   (`SHA256(venue_ref|event_ref|UTC_date)`). This one hashes `UTC_time` as **`HH:MMZ`**.
   Copying the previous solution's format produces a well-formed 64-hex string that the
   endpoint rejects. Read the format string every time.

4. **Subtracting the offset from the hour only.** `hh -= offset` without normalising
   through minutes and days happens to work for `+02:00` at `21:00`. It breaks on negative
   offsets and on times near midnight. The solver carries minutes-since-midnight and
   re-divides, so the day rolls correctly in both directions.

5. **Trusting `civic-directory.json`.** It is keyed by *station* refs (10 hex), not
   *voyage* refs (16 hex). Nothing in it is referenced by any clue. Its `district`/`roof`/
   `seats` columns are pure filler carried over from the sibling challenge's schema.

6. **Chasing the `console` JS branch.** Third sighting of the same inert template artifact.
   `/console` 404s.

7. **Assuming the datasets are unordered.** They are index-aligned: `voyages.json[i]` and
   `tide-station.csv[i]` share a station for all 60 rows. That alignment is what makes the
   generator readable — and reading it is what reveals that station is a *periodic* key
   rather than a unique one.

---

## 10. Remediation Notes

There is no exploitable vulnerability class here; the endpoint performs exact-match
validation on a SHA-256 commitment and returns a uniform 403 on any mismatch, which is
correct. Notes if this generator is reused:

- **Key the decoy on something the receipt cannot use — or state that it is a decoy.** A
  neighbouring dataset sharing a schema with a sibling challenge, while being keyed on a
  *different* identifier than the one the receipt needs, is good misdirection but is also
  the kind of artifact that in a real pipeline produces a confidently wrong answer rather
  than an obvious dead end.
- **The ambiguous key is the whole challenge, so keep it honest.** Station duplication
  (24/36 stations) is what creates the difficulty, and it is fair because four independent
  attributes disambiguate. If a future variant reduced that to one disambiguating
  attribute, the challenge would degrade from reasoning to guessing.
- **If the receipt ever gates anything of value**, the `SHA256(a|b|c)` scheme is sound only
  because the server compares the *hash* and never echoes the expected preimage. Keep the
  comparison constant-time and keep the input space off the wire.

---

## 11. Reproduce in One Block

```bash
set -e
cd /tmp && mkdir -p blue-meridian && cd blue-meridian

curl -s -O http://54.72.82.22:8500/downloads/field-notes.zip
unzip -o field-notes.zip >/dev/null

R=$(python3 - <<'PY'
import csv, hashlib, json

voy    = json.load(open("voyages.json"))
tide   = list(csv.DictReader(open("tide-station.csv")))
camera = json.load(open("camera-metadata.json"))

# pier-note.txt: gauge 219 cm; clock and compass serviced -> trust the metadata
stations = {r["station"] for r in tide if int(r["tide_cm"]) == 219}
assert len(stations) == 1, stations
station_ref = stations.pop()

# camera-metadata.json: 2026-06-04T21:00:00 at +02:00 -> 19:00Z
sign  = 1 if camera["utc_offset"][0] == "+" else -1
oh, om = (int(x) for x in camera["utc_offset"][1:].split(":"))
hh, mm = (int(x) for x in camera["local_time"].split("T")[1].split(":")[:2])
t = hh * 60 + mm - sign * (oh * 60 + om)
utc_hhmm = f"{t % 1440 // 60:02d}:{t % 60:02d}Z"

exp = {"tide_cm": 219, "utc_hour": int(utc_hhmm[:2]),
       "bearing": camera["compass_degrees"], "vessel": camera["vessel_mark"]}

hits = [v for v in voy
        if v["station"] == station_ref
        and all(v[k] == val for k, val in exp.items())]
assert len(hits) == 1, hits

voyage_ref = hits[0]["ref"]
print(hashlib.sha256(f"{voyage_ref}|{station_ref}|{utc_hhmm}".encode()).hexdigest())
PY
)

echo "receipt = $R"
curl -s -X POST http://54.72.82.22:8500/submit \
     -H 'Content-Type: application/json' \
     -d "{\"answer\":\"$R\"}"
# {"message":"safctf{756f7d81426571a6d6dac9b1aae5f271}","ok":true}
```

---

## 12. Flag

```
safctf{756f7d81426571a6d6dac9b1aae5f271}
```

---

*Artifacts for this challenge live in `blue-meridian/`: `field-notes.zip`,
`voyages.json`, `tide-station.csv`, `camera-metadata.json`, `pier-note.txt`,
`submission.txt`, `civic-directory.json`, `solve.py`.*

*Sibling challenges on the same host, same generator, escalating join complexity:*
*— **Paper Lanterns** (`:8480`, 200 pts): single-source filter, tie-break by year.*
*— **Last Tram Home** (`:8490`, 300 pts): two-key join with a local→UTC conversion.*
*— **Blue Meridian** (`:8500`, 550 pts): five-attribute join against an ambiguous station key.*
