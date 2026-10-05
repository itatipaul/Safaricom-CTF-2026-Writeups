# Matchday Replay — Safcom CTF (forensics, 200 pts)

> The afternoon crowd is still singing. The match is over, but something was left
> behind in the replay system. Old plays, old moments, and old data are still being
> served. Not everything in the archive belongs on the screen.
> Can you find what the replay was never meant to show?
>
> **Target:** http://54.72.82.22:8450

**Flag:** `safctf{e2d6cc7b320577dd3eb54aa08f86e446}`

---

## TL;DR

A downloadable `replay.zip` contains a packet capture of a bespoke layer-2 protocol
plus a session log. The capture's `LIVE` frames are out-of-order fragments of a
44-byte payload. The session log leaks the "replay card" id `afterglow-17`. The
payload is the flag-shaped token

```
safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
```

XOR-encrypted with a keystream that is **the first 12 bytes of `SHA-256("afterglow-17")`
repeated** (period 12 — *not* the usual full 32-byte digest). Submitting that token to
`/submit` returns the real flag.

---

## 1. Recon

The landing page (`/`, 3592 bytes, Werkzeug/3.1.9 Python/3.11.16) advertises a
"Collection desk" download:

```html
<a class="download" href="/downloads/replay.zip">replay.zip</a>
```

```console
$ curl -sI http://54.72.82.22:8450/downloads/replay.zip
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: application/zip
```

The site's inline JS posts `JSON.stringify({answer: ...})` to `/submit`, so that is
where a recovered token goes.

```console
$ curl -s -o replay.zip http://54.72.82.22:8450/downloads/replay.zip
$ ls -l replay.zip
-rw-r--r-- 1 havoc havoc 2145 Oct  2 11:30 replay.zip
$ unzip -l replay.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     3276  ...         capture.pcap
       91  ...         session.log
```

*(Differential check of the zip: 2 local file headers, EOCD with `entries=2`,
zero trailing bytes — the container hides nothing. The secret is inside the pcap.)*

`session.log` is the only human-readable clue:

```
18:44 volunteers crossed the end line
18:48 lights lowered
19:02 replay card: afterglow-17
```

That last line is a credential: the **replay card id `afterglow-17`**.

## 2. The capture is a custom protocol, not TCP/IP

```console
$ file capture.pcap
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4
              (raw IP), capture size 262144 bytes
```

Linktype **147 = `LINKTYPE_RAW`** with no IP inside — the frames are a bespoke
format, so Wireshark's dissectors get nothing. Frame counts:

| Tag    | Count | Wire format                                        |
|--------|------:|----------------------------------------------------|
| `IDLE` |    80 | `"IDLE"` + 18 random bytes (22 B) — noise/padding   |
| `LIVE` |     7 | `"LIVE"` + `u16 BE seq` + `u16 BE len` + payload   |

Parsing the 24-byte pcap global header and walking each `(ts, incl, orig, data)`
record yields the seven `LIVE` frames (they appear **out of order** in the capture —
seqs 2, 5, 1, 4, 6, 0, 3):

| pkt | ts offset | seq | len | payload (hex)      |
|----:|----------:|----:|----:|--------------------|
|  4  |         4 |  2  |  7  | `b4e83f2a3822e2`   |
| 26  |        26 |  5  |  7  | `72e9c7bda33828`   |
| 32  |        32 |  1  |  7  | `76fafbb326bbc4`   |
| 33  |        33 |  4  |  7  | `37282222f8abe1`   |
| 40  |        40 |  6  |  2  | `6d3e`             |
| 41  |        41 |  0  |  7  | `ac95e2a67b7d74`   |
| 42  |        42 |  3  |  7  | `fabe71ead9e5fd`   |

Sorting by the sequence field and concatenating gives a 44-byte message
(7·6 + 2):

```
ac95e2a67b7d7476fafbb326bbc4b4e83f2a3822e2fabe71ead9e5fd37282222f8abe172e9c7bda338286d3e
```

The `seq` field is the offset key — this is IP-style fragment reassembly on a
custom link layer. The 80 `IDLE` frames carry uniformly random bytes and are
decoy traffic ("old plays, old moments" that were never meant to be shown);
XORing them against the payload in any alignment produces nothing printable.

## 3. Recovering the keystream

44 bytes is exactly the right size for a flag (`safctf{` + 36-char body + `}`):
the token is a UUID. The obvious hypothesis is a repeating-key XOR with the card id.

Deriving the keystream from a known prefix is the fastest way in: a Safcom flag
starts with `safctf{`, so

```
keystream[0:7] = ciphertext[0:7] XOR "safctf{"
               = dff484c50f1b0f
```

which is **exactly `SHA-256("afterglow-17")[0:7]`**:

```
$ python3 -c 'import hashlib;print(hashlib.sha256(b"afterglow-17").hexdigest())'
dff484c50f1b0f43cfce8740ab2eb769ff419a6e848053e32dcf55b0a09a12fc
```

So the key material is `SHA-256(card_id)`. The trap is the period. Using the full
32-byte digest as a repeating keystream decrypts the first 12 bytes cleanly —
`safctf{5554f` — and then turns to garbage at index 12:

```python
>>> bytes(a^b for a,b in zip(C, (sha256(key).digest()*2)[:44]))
b"safctf{5554f\x10\xea\x03\x81\xc0k\xa2Lfz\xed..."   # dies at byte 12
```

That failure *at exactly 12* is the tell: the developer truncated the digest to
**12 bytes** and repeated that. With a 12-byte period the whole message falls out:

```python
>>> K = hashlib.sha256(b"afterglow-17").digest()[:12]   # dff484c50f1b0f43cfce8740
>>> ks = (K * 4)[:44]
>>> bytes(a^b for a,b in zip(C, ks))
b'safctf{5554fd00-017a-4915-a883-a7ef2639f73b}'
```

Decryption, byte by byte:

| ciphertext                                      | keystream (12 B, repeated) | plaintext   |
|-------------------------------------------------|----------------------------|-------------|
| `ac95e2a67b7d74`                                | `dff484c50f1b0f`           | `safctf{`   |
| `76fafbb326bbc4`                                | `43cfce8740dff484`         | `5554fd00`  |
| `b4e83f2a3822e2`                                | `c50f1b0f43cfce87`         | `-017a-49`  |
| `fabe71ead9e5fd`                                | `40dff484c50f1b0f`         | `15-a883-`  |
| `37282222f8abe1`                                | `43cfce8740dff484`         | `a7ef2639`  |
| `72e9c7bda33828` + `6d3e`                       | `c50f1b0f43cfce87` + `40df`| `f73b}`     |

**Replay token:** `safctf{5554fd00-017a-4915-a883-a7ef2639f73b}`

## 4. Exchange the token for the flag

```console
$ curl -s http://54.72.82.22:8450/submit \
    -H 'Content-Type: application/json' \
    --data '{"answer":"safctf{5554fd00-017a-4915-a883-a7ef2639f73b}"}'
{"message":"safctf{e2d6cc7b320577dd3eb54aa08f86e446}","ok":true}
```

Control requests confirm `/submit` really validates (a wrong or empty answer is
rejected):

```console
$ curl -s ... --data '{"answer":"safctf{deadbeef}"}'
{"message":"The request could not be completed.","ok":false}
$ curl -s ... --data '{"answer":""}'
{"message":"The request could not be completed.","ok":false}
```

---

## Flag

```
safctf{e2d6cc7b320577dd3eb54aa08f86e446}
```

## Files

- `solve.py` — end-to-end solve (fetch → parse → reassemble → decrypt → submit).

## Lessons / puzzle design notes

- **`seq` on a custom L2 header is fragment reassembly.** When a capture has no IP,
  count frames by their ASCII tag and read the header layout off the raw bytes
  (`struct`/`xxd` beats a dissector).
- **Decoy traffic is real traffic.** The 80 `IDLE` frames exist to bury 7 real ones
  and to bait keystream/XOR rabbit holes — nothing in them is meaningful.
- **A known plaintext prefix is the whole game.** `safctf{` turns "unknown cipher"
  into "known keystream"; the derived `dff484c50f1b0f` immediately fingerprints as
  `SHA-256(card_id)`.
- **Watch the period, not just the algorithm.** The first 12 bytes decoding cleanly
  under the *full* digest looks like success — the divergence at exactly byte 12 is
  the hint that the digest was truncated to 12 bytes.
- The "card id" in a log line is a credential. Logs are data the player is meant to
  join against the capture.
