# Parallel Lines — Writeup

**Category:** Crypto (stream cipher / keystream reuse) | **Points:** 350

> Two paths run side by side, close enough to seem connected but never quite meeting.

**Flag:** `safctf{8d6447b3f694f59efef1f015f58d04a7}`

---

## TL;DR

Two files were encrypted with the **same keystream** (a two-time pad). One has a known plaintext (`memo.txt`), so XORing it with its ciphertext recovers the keystream. A decoy shuffle (`spool_order`) hides the byte order; undoing it with the inverse permutation reveals the second plaintext, a "collection receipt". Submitting the receipt to `/submit` returns the real flag.

---

## Recon

Service: `http://54.72.82.22:8430` (Flask/Werkzeug). The landing page offers one download, `lookbook.zip`, at `/downloads/lookbook.zip`. (`/lookbook.zip` returns a 404 HTML page, not an archive.) The inline JS posts `{"answer": ...}` to `/submit`.

Archive contents:

| File | Size | Notes |
|---|---|---|
| `memo.txt` | 153 B | Known plaintext: "Studio memo: sample garments arrive Tuesday. Keep the silver rack clear. ....." |
| `export-a.bin` | 153 B | Same length as the memo, so likely the memo's ciphertext |
| `export-b.bin` | 64 B | Unknown ciphertext |
| `spool.json` | 741 B | `nonce`, plus `spool_order`, a permutation of 0..152 |

Checks: `export-a` and `memo.txt` are both 153 bytes, and `spool_order` has 153 entries that are exactly the set {0..152}, so it is a permutation of the memo/export-a length.

## Idea ("two paths side by side")

Two ciphertexts share one keystream `K`:

```
A = M ^ K     (M = memo.txt, known)
B = P ^ K     (P = unknown)
```

Knowing `M` gives `K = A ^ M`, and then `P = B ^ K`. The 64-byte `B` only needs the first 64 keystream bytes.

A naive `K = A ^ M` gives garbage for `P`, so the byte order is scrambled. `spool_order` is the hint: the stored `export-a` bytes are in a shuffled order relative to the keystream.

## Solution

Undo the shuffle on `export-a` using the **inverse** permutation, then XOR:

```python
import json
m  = open("memo.txt","rb").read()
a  = open("export-a.bin","rb").read()
b  = open("export-b.bin","rb").read()
sp = json.load(open("spool.json"))["spool_order"]

inv = [0]*len(sp)
for i, p in enumerate(sp):
    inv[p] = i

a2 = bytes(a[inv[i]] for i in range(len(a)))      # un-shuffle export-a
ks = bytes(x ^ y for x, y in zip(a2, m))          # keystream
print(bytes(x ^ y for x, y in zip(b, ks)))        # decrypt export-b
```

Output:

```
b'Collection receipt: safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}'
```

I tried the other permutation/direction combinations as well (direct, `spool_order` instead of its inverse, permuting the memo or the keystream instead); only the inverse-on-`export-a` variant gave readable text. The `nonce` field was not needed.

## Redeeming the receipt

As with the earlier "Three Encores" challenge, the recovered string is not the final flag; the service swaps it for the real one:

```bash
curl -i -X POST http://54.72.82.22:8430/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}"}'
# {"message":"safctf{8d6447b3f694f59efef1f015f58d04a7}","ok":true}
```

## Takeaways

- Reusing a keystream (same key/nonce) in any stream cipher or CTR/OTP-style scheme is fatal: `A ^ B = M ^ P`, and any known plaintext yields the keystream outright.
- Obfuscating byte order with a shuffle adds no security if the permutation is shipped alongside the data.
- When a plausible-looking flag is just a "receipt", try posting it to the challenge service's `/submit`.

**Flag:** `safctf{8d6447b3f694f59efef1f015f58d04a7}`
