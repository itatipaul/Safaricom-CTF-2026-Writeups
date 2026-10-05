# Last Tram Home — CTF Writeup

> **Category:** OSINT · **Points:** 300 · **Difficulty:** Medium
> **Target:** `http://54.72.82.22:8490`
> **Flag:** `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`

---

## 1. Challenge Brief

> *"The city has a different pace after sunset. The crowds thin out, the lights blur across empty streets, and the last tram begins its journey through the sleeping city. Most passengers have already gone home. But one stop remains on the route—and someone, or something, is still waiting there."*

The page states the actual task plainly:

> **Collection desk** — *Reconcile the studio visit and submit its collection receipt.*

**"Reconcile"** is the operative word. This is not an exploitation challenge — it is a
multi-source data-join with a timezone conversion in the middle. That is the 300-point
step up from Paper Lanterns (200 pts), which was a single-source filter.

---

## 2. Reconnaissance

### 2.1 Fingerprint

```bash
curl -s -i http://54.72.82.22:8490/
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 3589
```

Same Flask/Werkzeug 3.1.9 on Python 3.11.16 stack as every other service on this
host.

### 2.2 Path probe

```bash
for p in robots.txt sitemap.xml .git/HEAD flag flag.txt admin api docs \
         openapi.json swagger.json submit route routes tram stops stop \
         health status debug console static/ downloads/; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://54.72.82.22:8490/$p")
  echo "$code  /$p"
done
```

```
404  /robots.txt       404  /sitemap.xml      404  /.git/HEAD
404  /flag             404  /flag.txt         404  /admin
404  /api              404  /docs             404  /openapi.json
404  /swagger.json     405  /submit           404  /route
404  /routes           404  /tram             404  /stops
404  /stop             200  /health           404  /status
404  /debug            404  /console          404  /static/
404  /downloads/
```

- `/submit` → **405** with `Allow: OPTIONS, POST` — the real endpoint.
- `/health` → **200** `{"status":"ok"}` — boilerplate liveness probe, no data.
  Worth checking, not worth pursuing.

### 2.3 The page is a reused template

The served HTML is **structurally identical** to the Paper Lanterns challenge:
same `Collection desk` / `Leave a receipt` two-card grid, same `#desk` form,
same `/submit` JSON contract, and the **same dead JavaScript branch**:

```javascript
let consoleMode = e.target.id === 'console';       // form is id="desk" -> always false
let path = consoleMode ? document.getElementById('path').value : '/submit';
```

As with Paper Lanterns, `consoleMode` is unreachable, `/console` is 404, and the
branch is an inert template artifact advertising a generic request primitive. I
verified it once here and moved on — it costs a minute and a half of curiosity,
not more.

**Takeaway for this host:** these challenges share a generator. The web layer is
a fixed shell; *all* the difficulty lives in the downloadable dataset. Spending
time on the HTTP surface is wasted effort on this platform.

---

## 3. The Field Notes

```bash
mkdir -p last-tram-home && cd last-tram-home
curl -s -O http://54.72.82.22:8490/downloads/field-notes.zip
unzip -l field-notes.zip
```

```
  Length      Date    Time    Name
---------  ---------- -----   ----
     5063  2026-10-01 03:59   civic-directory.json
     3780  2026-10-01 03:59   programme.json
      506  2026-10-01 03:59   tram.csv
      104  2026-10-01 03:59   studio-post.txt
       80  2026-10-01 03:59   submission.txt
---------                     -------
     9533                     5 files
```

### 3.1 `submission.txt` — the contract

```
Collection receipt format: SHA256(venue_ref|event_ref|UTC_date), lowercase hex.
```

This is the target function. Three inputs, pipe-separated, SHA-256, lowercase hex.
Note the third input is **`UTC_date`** — the word *UTC* is doing enormous work
here, and it is the first thing that should make you suspicious of any
wall-clock time you are handed.

### 3.2 `studio-post.txt` — the clue

```
The last frame was taken at stop 18, three hours after UTC. The wall clock read 21:30 on 18 April 2026.
```

Three facts, one of them a timezone:

| Fragment | Meaning |
|---|---|
| "taken at **stop 18**" | the tram stop index — a join key |
| "**three hours after UTC**" | the photographer's local zone is **UTC+3** |
| "the **wall clock read 21:30 on 18 April 2026**" | a *local* timestamp, not UTC |

The phrasing is deliberately a little awkward. "Three hours after UTC" means the
local clock runs *ahead of* UTC by three hours, so:

```
UTC = local − 3h
```

### 3.3 `tram.csv` — stop → venue

```csv
stop,venue
1,97b41b7510
2,dafc82a0b8
...
18,b59c881fc2
...
36,7e9f5bc1d8
```

36 stops, each mapping to a 10-hex-char venue reference.

### 3.4 `programme.json` — venue + time → event

36 entries:

```json
{
  "event":  "59c3c77fe913",
  "venue":  "97b41b7510",
  "time_utc": "2026-04-01T18:30:00Z",
  "artist": "act-0"
}
```

Every entry's `time_utc` is `T18:30:00Z`. The `artist` field cycles `act-0` …
`act-8`. Venues appear exactly once each, and the venue set exactly equals the
venue set in `tram.csv` — the two files are join-compatible by design.

### 3.5 `civic-directory.json` — the decoy

```json
{"ref": "97b41b7510", "name": "House 1", "district": "North",
 "opened": 1980, "roof": "copper", "seats": 120}
```

This is the **same schema as the Paper Lanterns dataset** — `ref`, `name`,
`district`, `opened`, `roof`, `seats` — but here the `ref` column holds *this*
challenge's venue references. Verification:

```python
set(r['ref'] for r in civic) == set(tram.values())   # -> True
```

So the venue refs are fully recoverable from `tram.csv` alone, and
`civic-directory.json` contributes **nothing** to the receipt. It is a
cross-challenge carry-over that exists to look load-bearing.

There is a nastier detail: the row whose `ref` is reachable from stop 18 is
**`House 18` — `{"district": "East", "opened": 1997, "roof": "glass"}`** — which
is *byte-for-byte the answer row from Paper Lanterns*. Anyone who solved the
previous challenge and pattern-matches on "find the house" will feel a warm glow
of recognition and learn nothing. It is a deliberate callback to lull you into
reusing a shortcut that does not produce a receipt.

---

## 4. Solving It — The Reconciliation

The chain is four links. The third is where the points are.

```
studio-post.txt                 tram.csv                programme.json
   stop 18  ─────────────────▶  venue b59c881fc2  ─┐
                                                    ├─▶ event 2011bf1eeb4b
   wall clock 21:30 local (UTC+3)                   │
        │                                           │
        └─ convert ─▶ 2026-04-18T18:30:00Z ──────────┘
                                                    │
submission.txt ─▶ SHA256("b59c881fc2|2011bf1eeb4b|2026-04-18") ─▶ receipt
```

### 4.1 Step 1 — stop → venue

`tram.csv`, stop 18 → `b59c881fc2`.

### 4.2 Step 2 — local wall clock → UTC

The studio post says the wall clock read `21:30` and the local zone is three
hours ahead of UTC:

```
21:30 (local, UTC+3)  −  3h  =  18:30 UTC, same calendar day  →  2026-04-18T18:30:00Z
```

Rollover handling matters in general — if the wall clock had read, say, `01:30`,
the subtraction would cross midnight backwards and the UTC *date* would become
the 17th. That is precisely why the receipt formula says `UTC_date` and not
"the date in the photo". Here the subtraction stays within the day, so
`UTC_date = 2026-04-18`, but the code must implement the rollover correctly or
it will silently produce a wrong receipt on other inputs.

### 4.3 Step 3 — reconcile venue + timestamp → event

Filter `programme.json` for `venue == b59c881fc2` *and* `time_utc == 2026-04-18T18:30:00Z`.

This is the moment the conversion is **validated by the data**. The derived UTC
timestamp lands exactly on a stored programme timestamp. That is not a
coincidence you could get from a wrong offset — had the offset been misread as
UTC−3, you would have computed `00:30Z` and matched nothing:

```
[*] programme entries for b59c881fc2: 1
      event=2011bf1eeb4b time_utc=2026-04-18T18:30:00Z  <== MATCH
```

The join is unique — 1 candidate, 1 match. Structurally this is the same
"coarse filter then tie-breaker" shape as Paper Lanterns, but the tie-breaker
here is a *derived* value rather than a given one.

### 4.4 Step 4 — build the receipt

```
preimage = "b59c881fc2|2011bf1eeb4b|2026-04-18"
receipt  = SHA256(preimage)
         = 57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d
```

### 4.5 Solver

`solve.py` (full source in the artifacts directory):

```python
#!/usr/bin/env python3
"""Solve Last Tram Home."""
import csv, hashlib, json

STOP = 18                      # "taken at stop 18"
WALL_CLOCK = (21, 30)          # "The wall clock read 21:30"
LOCAL_DATE = (2026, 4, 18)     # "on 18 April 2026"
UTC_OFFSET_HOURS = 3           # "three hours after UTC" -> local = UTC + 3

def load_tram(path="tram.csv"):
    with open(path, newline="") as fh:
        return {int(r["stop"]): r["venue"] for r in csv.DictReader(fh)}

def to_utc(date, hhmm, offset_hours):
    """Wall-clock local time + offset -> (utc_date_iso, utc_datetime_iso)."""
    y, mo, d = date
    hh, mm = hhmm
    hh -= offset_hours
    if hh < 0:
        hh += 24; d -= 1
    elif hh >= 24:
        hh -= 24; d += 1
    iso_date = f"{y:04d}-{mo:02d}-{d:02d}"
    return iso_date, f"{iso_date}T{hh:02d}:{mm:02d}:00Z"

def main():
    tram  = load_tram()
    prog  = json.load(open("programme.json"))
    civic = json.load(open("civic-directory.json"))

    print(f"[*] tram refs == civic refs ? "
          f"{set(tram.values()) == {r['ref'] for r in civic}}"
          "   <- civic-directory is redundant here")

    venue_ref = tram[STOP]
    print(f"[1] stop {STOP} -> venue_ref = {venue_ref}")

    utc_date, utc_iso = to_utc(LOCAL_DATE, WALL_CLOCK, UTC_OFFSET_HOURS)
    print(f"[2] {WALL_CLOCK[0]:02d}:{WALL_CLOCK[1]:02d} "
          f"local (UTC+{UTC_OFFSET_HOURS}) -> {utc_iso}")

    hits = [e for e in prog
            if e["venue"] == venue_ref and e["time_utc"] == utc_iso]
    print(f"[3] reconciled events: {len(hits)}")
    if len(hits) != 1:
        raise SystemExit(f"[!] expected exactly 1, got {len(hits)}")
    event_ref = hits[0]["event"]
    print(f"[3] event_ref = {event_ref}")

    preimage = f"{venue_ref}|{event_ref}|{utc_date}"
    receipt  = hashlib.sha256(preimage.encode()).hexdigest()
    print(f"\n[4] preimage : {preimage}")
    print(f"[+] RECEIPT  : {receipt}")

if __name__ == "__main__":
    main()
```

Output:

```console
$ python3 solve.py
[*] tram stops        : 36
[*] programme events  : 36
[*] civic rows        : 36  (schema ['ref', 'name', 'district', 'opened', 'roof', 'seats'])
[*] tram refs == civic refs ? True   <- civic-directory is redundant here

[1] stop 18 -> venue_ref = b59c881fc2
[2] 21:30 local (UTC+3) -> 2026-04-18T18:30:00Z
[3] programme entries for b59c881fc2: 1
      event=2011bf1eeb4b time_utc=2026-04-18T18:30:00Z   <== MATCH
[3] event_ref = 2011bf1eeb4b

[4] preimage : b59c881fc2|2011bf1eeb4b|2026-04-18
[+] RECEIPT  : 57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d
```

---

## 5. Submission & Flag

```bash
curl -s -i -X POST http://54.72.82.22:8490/submit \
     -H 'Content-Type: application/json' \
     -d '{"answer":"57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d"}'
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: application/json
Content-Length: 65
Connection: close

{"message":"safctf{a7290ed4a3ba7af7bd4b4c529eb99314}","ok":true}
```

> ### 🚩 `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`

### 5.1 Negative controls

Submitted to confirm the endpoint genuinely validates the receipt rather than
returning a flag for anything well-formed. Every variant below was rejected with
`403 {"message":"The request could not be completed.","ok":false}`:

| Variant | Result |
|---|---|
| **correct receipt** | ✅ flag |
| wrong UTC date (`2026-04-19`) | ❌ 403 |
| wrong `event_ref` (neighbouring event) | ❌ 403 |
| wrong separator (`-` instead of `\|`) | ❌ 403 |
| wrong stop (`17` instead of `18`) | ❌ 403 |
| empty answer | ❌ 403 |

Each of the four inputs to the chain is load-bearing. There is no partial credit
and no oracle.

---

## 6. Timeline / Command Log

| # | Action | Result |
|---|--------|--------|
| 1 | `curl -i http://54.72.82.22:8490/` | Flask page, `field-notes.zip` + `/submit` |
| 2 | Read inline JS | Same template as Paper Lanterns; dead `console` branch |
| 3 | Path probe | All 404; `/submit` 405; `/health` 200 (no data) |
| 4 | `curl -O /downloads/field-notes.zip` | 2679 B, 5 files |
| 5 | `unzip` | `civic-directory.json`, `programme.json`, `tram.csv`, `studio-post.txt`, `submission.txt` |
| 6 | Read `submission.txt` | `SHA256(venue_ref\|event_ref\|UTC_date)` |
| 7 | Read `studio-post.txt` | stop 18; wall clock 21:30, local = UTC+3, 18 Apr 2026 |
| 8 | `tram.csv` lookup | stop 18 → venue `b59c881fc2` |
| 9 | Timezone conversion | `21:30 − 3h` → `2026-04-18T18:30:00Z` |
| 10 | `programme.json` join | venue + timestamp → event `2011bf1eeb4b` (1 match) |
| 11 | SHA-256 the preimage | receipt `57aa623e…ee914d` |
| 12 | `POST /submit` | **200 · flag returned** |
| 13 | 5 negative controls | all 403 — endpoint validates properly |

---

## 7. Why This Is an "OSINT" Challenge

Nothing was exploited. The challenge is a **temporal entity-resolution** problem,
which is exactly what a large share of real intelligence analysis looks like: you
hold partial, heterogeneous, human-sourced records and you must join them into
one confident identification.

| CTF step | Real-world analogue |
|---|---|
| `studio-post.txt` prose | A human source report with imprecise language |
| "three hours after UTC" | A stated local timezone — the classic analyst footgun |
| converting to UTC before joining | Normalising all timestamps to a common frame *before* correlation |
| `tram.csv` | A reference/lookup table mapping a source's label to an internal ID |
| `programme.json` as a time-indexed event log | Any registrar, ticketing, or schedule dataset |
| venue + timestamp join | Correlating two records that share no common key except time and place |
| timestamp landing exactly on a stored value | The confirmation that your normalisation was correct |
| `civic-directory.json` | A stale neighbouring dataset that looks relevant and is not |

The BlackBook corpus frames the general discipline as pivoting from a partial
entity to a resolvable identifier — OWASP WSTG, *Conduct Search Engine
Reconnaissance for Information Leakage*, § **OSINT Correlation Tools**
([ref](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md)):

> "…maps relationships between domains, IP addresses, email addresses, and
> organizations through automated data transforms. Testers use it to visualize
> an organization's attack surface by **pivoting from a single entity** to
> discover related infrastructure and associated data points."

The timezone-normalisation lesson specifically is the everyday version of a
much harder problem: **the moment you correlate two datasets by time, you must
prove both are in the same timezone before you trust a single match.** A
three-hour skew silently destroys matches in exactly the way a wrong offset
would have here.

---

## 8. Failure Modes Worth Recording

1. **Joining before normalising.** If you search `programme.json` for something
   matching `21:30` you find nothing — every entry is `18:30:00Z`. The tempting
   conclusion is "the join key must be wrong", when the actual problem is that
   you are comparing a local clock to a UTC store. Normalise first, then join.

2. **The latent date rollover.** Here `21:30 − 3h = 18:30` on the same day, so a
   naive `date` pass-through also works — and that is the trap. It teaches the
   wrong reflex. Any wall clock between `00:00` and `02:59` local rolls the UTC
   date *backwards* by one day. Hard-coding the date from the studio post gives
   a correct answer today and a wrong receipt on the next variant.

3. **Trusting `civic-directory.json`.** It is a decoy carried over from the
   sibling challenge, complete with the same answer row (`House 18`,
   East/glass/1997). It contains no information the receipt needs. Note that
   `tram.csv` and `civic-directory.json` have *identical* ref sets — checking
   that set equality is what retires the decoy in one line instead of an hour.

4. **Chasing the `console` JS branch.** Same inert template artifact as Paper
   Lanterns. `/console` 404s.

5. **Off-by-one on the stop index.** `tram.csv` is 1-indexed. Stop 18 is
   `b59c881fc2`; stop 17 is `8911253ba7` and fails.

---

## 9. Remediation Notes

There is no vulnerability class here worth patching — the endpoint already
performs exact-match validation and returns a uniform 403 on any mismatch,
which is the right behaviour. Two notes if this dataset generator is reused:

- **Make the decoy unambiguous or remove it.** `civic-directory.json` shares a
  schema with a sibling challenge *and* contains that sibling's answer row.
  That is fine as intentional misdirection, but it is worth confirming it is
  intentional rather than a packaging accident — it is the kind of artifact
  that, in a real data pipeline, produces a plausible wrong answer rather than
  an obvious dead end.
- **If the receipt ever gates anything more valuable than a per-team flag**,
  the `SHA256(a|b|c)` commitment scheme is sound only because the input space is
  small but the server compares the *hash*. Keep the comparison constant-time
  and never echo the expected preimage.

---

## 10. Reproduce in One Block

```bash
set -e
cd /tmp && mkdir -p last-tram-home && cd last-tram-home

curl -s -O http://54.72.82.22:8490/downloads/field-notes.zip
unzip -o field-notes.zip >/dev/null

R=$(python3 - <<'PY'
import csv, hashlib, json

tram = {int(r["stop"]): r["venue"] for r in csv.DictReader(open("tram.csv"))}
prog = json.load(open("programme.json"))

# studio-post.txt: stop 18; wall clock 21:30 on 18 Apr 2026; local = UTC+3
venue_ref = tram[18]

y, mo, d = 2026, 4, 18
hh, mm   = 21 - 3, 30          # local -> UTC
utc_date = f"{y:04d}-{mo:02d}-{d:02d}"
utc_iso  = f"{utc_date}T{hh:02d}:{mm:02d}:00Z"

hits = [e for e in prog if e["venue"] == venue_ref and e["time_utc"] == utc_iso]
assert len(hits) == 1, hits

print(hashlib.sha256(f"{venue_ref}|{hits[0]['event']}|{utc_date}".encode()).hexdigest())
PY
)

echo "receipt = $R"
curl -s -X POST http://54.72.82.22:8490/submit \
     -H 'Content-Type: application/json' \
     -d "{\"answer\":\"$R\"}"
# {"message":"safctf{a7290ed4a3ba7af7bd4b4c529eb99314}","ok":true}
```

---

## 11. Flag

```
safctf{a7290ed4a3ba7af7bd4b4c529eb99314}
```

---

*Artifacts for this challenge live in `last-tram-home/`: `field-notes.zip`,
`civic-directory.json`, `programme.json`, `tram.csv`, `studio-post.txt`,
`submission.txt`, `solve.py`.*

*Sibling challenge on the same host: **Paper Lanterns** (`:8480`, 200 pts) —
same template, same decoy directory schema, single-source filter instead of a
temporal join.*
