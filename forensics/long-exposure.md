# Long Exposure — Writeup

**Category:** Forensics | **Points:** 350

> Some moments belong to the blue hour.
> Connect to the challenge web service: `http://54.72.82.22:8470`

**Flag:** `safctf{f4946c9564b982892e9d41315b3ec739}`

---

## TL;DR

A memory dump holds a plaintext marker (`EVPCTX03`) with an AES-256 key right behind it. A packet capture holds a 72-byte AES-GCM message smuggled out as base32 DNS labels, split into 8 out-of-order chunks. Each chunk has to be base32-decoded **on its own**, not joined and decoded as one string. Decrypting gives a flag-shaped string that the CTF platform rejects. It is a token: POSTing it to the challenge service's `/submit` endpoint returns the real flag as the "collection receipt".

---

## Recon

The service at `:8470` is a fake photography site with one download, `field-kit.zip`, and a footer line: *"Keep your collection receipt when your visit is complete."* The page's inline JS posts `{"answer": ...}` to `/submit`, but no form is rendered. A plain `GET /submit` returns `405` with `Allow: POST, OPTIONS`.

The zip contains four files:

| File | Notes |
|---|---|
| `field-note.txt` | *"The camera spool retained a warm buffer after the blue-hour test. Original and processed takes were exported together."* |
| `modules.map` | `00001000-00009000 rw-p studio-worker` |
| `process.core` | 32768 bytes (exactly `0x9000 - 0x1000`), a dump of that region |
| `uplink.pcap` | 158 packets, link type 147 (user-defined), so Wireshark won't dissect it |

`modules.map` matters for one reason: it gives the load base `0x1000`, so file offset = virtual address − `0x1000`.

## The memory dump

`process.core` is statistically random end to end (entropy ≈ 7.99 bits/byte, no repeated 16-byte blocks, no AES key schedules, no pointers into the mapped range). Rendering it as an image, at several widths and as bit planes, also shows only static.

The only plaintext in it is an 8-byte tag:

```
VA 0x2b70 (file offset 0x1b70):  45 56 50 43 54 58 30 33   "EVPCTX03"
```

Everything after it looks random, which is what a raw key would look like. Hold that thought.

## The packet capture

```text
150 packets  magic "NOI"      3-byte magic + 40-byte payload
  8 packets  magic "QRY\x00"  magic + 1-byte index + a DNS-style label
```

- **`NOI`**: pure noise. No correlation between packets, no bit bias, no overlap with the core, and nothing decrypts under any key I could build. These are decoys.
- **`QRY`**: look like DNS exfil:

  ```
  idx 0  PZRA3C5MF2WARTI.img.field.test
  idx 1  6CYYWT3ECKT45IY.img.field.test
  ...
  idx 7  UORLITSJBNLJVUI.img.field.test
  ```

  They arrive out of order (3, 1, 7, 6, 2, 5, 4, 0), so the index byte gives the real order. The labels are base32.

### The decoding trap

Each label is **15** base32 characters = 75 bits, which is not a whole number of bytes. The natural first attempt (concatenate all labels, then decode) yields 75 bytes with misaligned bits, and nothing downstream works.

The correct reading: the sender encoded **each 9-byte chunk separately**. 9 bytes encode to 15 characters plus one `=` pad, and the pad is dropped because it can't appear in a DNS label. Re-pad each label to 16 characters and decode it on its own:

```
idx 0  PZRA3C5MF2WARTI  ->  7e620d8bac2eac08cd   (9 bytes)
idx 1  6CYYWT3ECKT45IY  ->  f0b18b4f6412a7cea3   (9 bytes)
...                                              8 x 9 = 72 bytes
```

72 bytes fits a very common layout: **12-byte nonce + 44-byte ciphertext + 16-byte GCM tag**.

## Recovering the key

With a clean 72-byte blob, brute force becomes easy: use every 16- and 32-byte window of `process.core` as an AES key and try AES-256-GCM (nonce = first 12 bytes, remainder = ciphertext + tag). GCM authenticates, so a wrong key can't produce a false positive. Exactly one window passes:

```
VA 0x2b78 (file offset 0x1b78), 32 bytes
6816c31d3e7805d2ea58a8ecf6aba07ed2766c3cadd24e37a6797d9466ebc059
```

That is the 32 bytes **immediately after the `EVPCTX03` tag**. Plaintext:

```
safctf{c9ddd1e9-f650-4bae-a650-5c9a92edabe4}
```

## The twist: it isn't the flag

Submitting that to the CTF platform returns **Incorrect**, even though the GCM tag verified, so the decryption is definitely right. The string doesn't match the flag format used elsewhere in the set (`safctf{` + 32 hex chars), and the service has a POST-only `/submit` endpoint plus the line about a "collection receipt". So the recovered UUID is a token to exchange with the service:

```bash
curl -s -X POST http://54.72.82.22:8470/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{c9ddd1e9-f650-4bae-a650-5c9a92edabe4}"}'
```

```json
{"message":"safctf{f4946c9564b982892e9d41315b3ec739}","ok":true}
```

## Solve script

Run from the extracted `field-kit.zip` directory (`pip install cryptography`):

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

Output: `safctf{c9ddd1e9-f650-4bae-a650-5c9a92edabe4}`, which you then POST to `/submit`.

## Dead ends (and why they were dead)

- **The 150 `NOI` packets.** Decoys. Tested for inter-packet correlation, bit bias, overlap with the core, and decryption under every 16/32-byte core window with several nonce layouts. All negative.
- **Entropy/visual analysis of the core.** Random everywhere except the marker. No hidden image, no relation between the two halves ("original and processed takes") at any lag.
- **AES key-schedule scan, pointer scan.** Nothing. The key is stored raw, not as an expanded schedule.
- **Passphrase/KDF guessing** from the flavour text (EVP_BytesToKey, PBKDF2). Nothing, because the key was stored raw, not derived.
- **Joining labels before decoding.** The 75-byte result is bit-misaligned. This cost me the most time, since every brute force over a wrong blob fails silently.
- **Treating the decrypted UUID as the flag.** It authenticated but was rejected, so it was a token for the service.

## Takeaways

- Check chunk alignment before concluding a key or cipher is wrong. If each piece's encoded length isn't a multiple of the encoding's block size, it was probably encoded **per chunk** with padding stripped.
- AEAD ciphers (GCM, ChaCha20-Poly1305) make brute force safe. The tag acts as an oracle with essentially no false positives, so sliding a key window over a memory dump is a valid first move.
- A short plaintext tag in an otherwise random dump (here `EVPCTX03`) is almost always a pointer to adjacent secret material. Try the bytes right after it first.
- "Incorrect" on a flag-shaped, authenticated plaintext often means an extra exchange step. Read the service's own hints (a POST-only `/submit`, a "receipt" line) before hunting for a second hidden payload.
- Statistical noise decoys cost time. Budget for them: test cheaply for structure (correlation, bias, overlap) and move on if there is none.

**Flag:** `safctf{f4946c9564b982892e9d41315b3ec739}`
