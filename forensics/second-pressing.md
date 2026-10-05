# Second Pressing — Safcom CTF (forensics, 250 pts)

> A favorite record deserves another listen.
> The needle drops, the familiar rhythm returns, and somewhere between the first
> play and the replay, something feels different.
> Maybe the track isn't quite finished with you yet.
> Listen closely. There's more hidden in the replay.
>
> **Target:** http://54.72.82.22:8460

**Flag:** `safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}`

---

## TL;DR

The download is a **SQLite database shipped with its write-ahead log**. The main
`library.db` is completely empty — every live row lives in the uncheckpointed
`library.db-wal`. Applying the WAL the normal way shows the *second* pressing:

```
(1, 'Test pressing', 'withdrawn')
```

but the WAL still contains an **earlier frame on the same page** holding the
*first* pressing, whose `receipt` column was overwritten with the literal string
`withdrawn`. That original receipt is a base64-encoded zlib blob:

```
eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==
        |
        +-- base64 -d --> zlib (78 9c) --> safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
```

That decoded value **is the flag**. It is not a token to be exchanged — the
`/submit` endpoint on this port is a **decoy** that returns a different,
flag-shaped string which the scoring platform rejects (see §6).

---

## 1. Recon

```console
$ curl -s http://54.72.82.22:8460/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 3614
```

The landing page is a small vinyl-store skin. Two things matter in it:

```html
<a class="download" href="/downloads/listening-room.zip">listening-room.zip</a>
...
<p>Keep your collection receipt when your visit is complete.</p>
```

"Keep your collection receipt when your visit is complete" is the hint: the
receipt is the artefact you're meant to recover — and, as it turns out, the
receipt *is* the flag.

The inline JS also defines a "console" mode that takes a `path`, a `method`, and
`headers` and fetches them — validating only that `path` starts with `/` and not
`//`:

```js
let consoleMode = e.target.id === 'console';
let path = consoleMode ? document.getElementById('path').value : '/submit';
if (!path.startsWith('/') || path.startsWith('//')) throw Error('Use a local service path.');
```

**This is a decoy.** The handler is bound with
`document.querySelector('form')?.addEventListener(...)` and the document contains
**no `<form>` element at all**, so the whole script is inert — neither the
`console` branch nor the `/submit` branch ever runs in the page.

The zip is tiny and fully accounted for:

```console
$ curl -s -o listening-room.zip http://54.72.82.22:8460/downloads/listening-room.zip
$ ls -l listening-room.zip
-rw-r--r-- 1 havoc havoc 1034 Oct  2 11:49 listening-room.zip
$ unzip -l listening-room.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8192  ...         library.db
     8272  ...         library.db-wal
    32768  ...         library.db-shm
       72  ...         desk.log
```

The container hides nothing: 4 local file headers, EOCD `entries=4`, zero bytes
after the EOCD, no zip comment, no second archive appended.

`desk.log` is the narration, and it is an exact description of what the database
did:

```
16:41 test pressing queued
16:42 catalogue revised
16:43 counter closed
```

Two writes — *queued* then *revised* — and then the connection closed **without a
checkpoint**, which is why the revision is still sitting in the WAL.

## 2. The database is empty

The schema:

```console
$ sqlite3 library.db .schema
CREATE TABLE pressings(id INTEGER PRIMARY KEY, title TEXT, receipt TEXT);
```

The contents:

```console
$ sqlite3 library.db 'select count(*) from pressings;'
0
```

**Zero rows.** The table exists but the data does not live in the main database
file. Notice the file-size fingerprint:

| file | size | interpretation |
|---|---:|---|
| `library.db` | 8192 | 2 pages — page 1 (`sqlite_master`) + page 2 (empty table) |
| `library.db-wal` | 8272 | 32-byte WAL header + **2 frames × 4120 bytes** |
| `library.db-shm` | 32768 | shared-memory index — **all zeros** apart from its header, no data |

The `-wal` size decomposes exactly: `32 + 2 × (24 + 4096) = 8272`. Two frames.
This is a WAL-mode database whose pages were never checkpointed back into the
main file.

## 3. Two states: first pressing vs second pressing

Opening the DB *normally* (letting SQLite apply the WAL) reveals the surviving
row — the "second pressing", i.e. the revised catalogue entry:

```console
$ sqlite3 library.db 'select id,title,receipt from pressings;'
1|Test pressing|withdrawn
```

The `receipt` is the literal string `withdrawn`. So the revision didn't just
change a title — it **overwrote the receipt**.

That is the trap the challenge is built around. That `sqlite3` invocation also
had a side effect worth knowing about:

```console
$ ls library.db-wal
library.db-wal
$ sqlite3 library.db 'select count(*) from pressings;' >/dev/null
$ ls library.db-wal
ls: cannot access 'library.db-wal': No such file or directory
```

**Opening the database checkpointed the WAL and deleted it.** Any investigation
that starts with "let me just open the db and look" destroys exactly the evidence
being hunted. Work on a copy, and read the WAL bytes *first*.

## 4. Reading the WAL by hand

The WAL format is simple enough to parse directly. A 32-byte header followed by
frames of `24-byte frame header + pagesize page image`:

```python
pagesize = int.from_bytes(wal[8:12], "big")   # 4096
offset = 32
while offset + 24 + pagesize <= len(wal):
    pgno   = int.from_bytes(wal[offset:offset+4],  "big")  # page number
    dbsize = int.from_bytes(wal[offset+4:offset+8],"big")  # db size after commit
    # salt:      wal[offset+8 :offset+16]
    # checksums: wal[offset+16:offset+24]
    # page:      wal[offset+24:offset+24+pagesize]
    offset += 24 + pagesize
```

A **nonzero `dbsize` marks a COMMIT frame**. Our WAL parses as:

```
[*] WAL magic : 0x377f0682  version 3007000  pagesize 4096
[*] salt      : 8a19174fe7ddea01
[*] frame0: offset=32    page=2  dbsize=2  (COMMIT)
[*] frame1: offset=4152  page=2  dbsize=2  (COMMIT)
```

Both frames write **page 2** — the `pressings` table's leaf page. In a WAL, later
frames for a page supersede earlier ones, so:

| frame | what it is | row |
|---|---|---|
| **frame 0** | the **first pressing** | `1, "Test pressing", <zlib+base64 blob>` |
| frame 1 | the **second pressing** | `1, "Test pressing", "withdrawn"` |

SQLite only ever surfaces frame 1. Frame 0 is stale-but-present: never
checkpointed, never overwritten, still perfectly readable in the file. The
"replay" in the challenge blurb is literal — the earlier take is still on the
tape.

Grepping the raw WAL for the giveaway is enough to find the payload, because
receipts are base64 and base64 of a zlib stream starts `eJ`:

```console
$ strings -a library.db-wal | grep -o 'eJ[A-Za-z0-9+/=]*' | sort -u
eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07T
eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==
```

Two candidates. The 72-character one ending in `==` is the complete receipt, and
it lives in **frame 0**. The 44-character one is a *fragment of that very same
string*, left behind in **frame 1's page**: when the revision replaced the long
record with the 9-byte `withdrawn`, SQLite shrank the cell in place and did not
zero the bytes the longer record had occupied, so the head of the original
receipt is still sitting there in stale page space. It is only a prefix, so
inflating it fails with `Error -5 ... incomplete or truncated stream` — exactly
the tell that it is a remnant rather than a second secret. Take the longest,
`==`-terminated match.

Locating both occurrences:

```console
off= 4080 len= 72  frame=0  page_off=4024   <- complete receipt, frame 0
    ctx: ..."\x00\x00\x00\x00Z\x01\x05\x00'\x81\x1dTest pressing" <<BLOB>> '\x00\x00\x00\x02...'
off= 8200 len= 44  frame=1  page_off=4024   <- stale remnant, frame 1
    ctx: ..."\x00\x00\x00\x00Z\x01\x05\x00'\x81\x1dTest pressing" <<BLOB>> "\x1a\x01\x04\x00'\x1fTest pressingwithd"...
```

The cell headers are readable straight off the page. Frame 0's cell is
`5a 01 05 00 27 81 1d` → payload `0x5a` (90), rowid 1, header length 5, serial
types `00` (NULL id) / `27` (13-byte text → `Test pressing`) / `81 1d`
(72-byte text → the receipt). Frame 1's is `1a 01 04 00 27 1f` → payload `0x1a`
(26), rowid 1, header length 4, serial types `00` / `27` / `1f` (9-byte text →
`withdrawn`). Same rowid, same page, same offset: a value replaced in place.

## 5. Decoding the receipt — this is the flag

The blob decodes in two steps — base64, then the zlib stream hiding inside it:

```python
>>> import base64, zlib
>>> s = "eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A=="
>>> raw = base64.b64decode(s)
>>> raw[:4].hex()
'789c2b4e'          # 78 9c = zlib, default compression
>>> zlib.decompress(raw)
b'safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}'
```

The compressed payload is a 37-byte `safctf{...}` value. Unlike the superficially
similar **Matchday Replay** puzzle (where the recovered UUID was a *token* to be
exchanged at `/submit` for the flag), here the decoded value is the flag itself.

## 6. The `/submit` endpoint is a decoy

Submitting the receipt looks like a success:

```console
$ curl -s http://54.72.82.22:8460/submit \
    -H 'Content-Type: application/json' \
    --data '{"answer":"safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}"}'
{"message":"safctf{34a793a0d11032abb97236fafc9b30c4}","ok":true}
```

`ok:true` and a `safctf{...}`-shaped 32-hex string is exactly what the **Matchday
Replay** service returns for a correct token, so it is very tempting to stop here.
**That value is not the flag — the scoring platform rejects it.**

The endpoint is not merely checking shape. Every well-formed but wrong answer is
refused with **HTTP 403**, including 32-hex values of exactly the right length:

```console
$ ... --data '{"answer":"safctf{00000000000000000000000000000000}"}'   -> 403 ok:false
$ ... --data '{"answer":"safctf{11111111111111111111111111111111}"}'   -> 403 ok:false
$ ... --data '{"answer":"safctf{deadbeefdeadbeefdeadbeefdeadbeef}"}'   -> 403 ok:false
$ ... --data '{"answer":"safctf{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"}' -> 403 ok:false
$ ... --data '{"answer":"safctf{deadbeef}"}'                           -> 403 ok:false
```

So it genuinely validates the receipt by value, and only the real receipt
unlocks it — yet the string it hands back is a dead end. Two further checks show
the returned value is not a derived artefact of the receipt but simply a
hardcoded decoy:

- the reply is byte-identical across repeat submissions (and the served zip is
  byte-identical too — `sha256` of `listening-room.zip` is the same on every
  fetch), so nothing is being computed per request;
- none of the obvious derivations reproduce it — `md5(receipt)`,
  `md5("safctf{"+receipt+"}")`, `sha256(receipt)[:32]` and
  `md5(uuid.UUID(receipt).bytes)` all miss.

The design is a two-stage trick: the service gives you a reward for finding the
receipt, and the reward is fake. The real answer is the receipt from the WAL.

---

## Flag

```
safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
```

*(recovered from WAL frame 0 — not the `/submit` reply
`safctf{34a793a0d11032abb97236fafc9b30c4}`, which the platform rejects)*

## Files

- `solve.py` — end-to-end: fetch → parse WAL frames → recover frame 0's receipt
  → base64+zlib → print the flag (and demonstrate the `/submit` decoy).

## Lessons / puzzle design notes

- **"Second pressing" is the whole design.** Two WAL frames on the same page are
  a first take and a re-take; the challenge asks you to hear the *first* one. The
  title, the blurb ("between the first play and the replay"), and `desk.log`
  (`test pressing queued` → `catalogue revised`) all point at the same idea.
- **A service returning a flag-shaped string is not proof it is the flag.** Here
  `/submit` validates the receipt correctly and then lies. Cross-check against
  the platform, and prefer the value you recovered from the artefact when a
  service hands you a suspiciously convenient answer. Note the same endpoint on
  **Matchday Replay (:8450)** *was* authoritative — the pattern is per-challenge,
  so verify rather than assume.
- **Never open the evidence.** A routine `sqlite3 library.db` checkpoints the WAL
  and deletes `-wal`. Read the raw bytes first; keep a pristine copy of the zip.
- **An empty main DB is a signal, not a dead end.** `0 rows` plus a ~2-page file
  next to a fat `-wal` means the data is entirely in the log.
- **The WAL is just frames.** 32-byte header; per frame a 24-byte header
  (pgno, dbsize, salt×2, checksum×2) and one page image; nonzero `dbsize` =
  commit. Earliest frame per page = prior state. No exotic tooling required.
- **The page's `console` is dead code.** The JS validates `path` for a "local
  service" but is bound to a `<form>` that does not exist in the document — a
  deliberate SSRF-flavoured decoy. Verify a sink actually fires before chasing it.
- **Pick the right duplicate.** The receipt turns up twice in the WAL: complete
  in frame 0, and as a 44-character stale remnant in frame 1's page, where the
  shorter `withdrawn` record was written over the longer one without clearing the
  freed space. The `==`-terminated, longest match is the genuine blob; the remnant
  is only a prefix and fails to inflate.
- **Layered encoding is cheap difficulty.** base64 → zlib is a two-line decode
  once you recognise the `eJ` / `78 9c` signature; it exists to make `strings`
  output look like noise.
