# Midnight Parcel — Writeup

**Category:** Crypto (CBC padding oracle) | **Points:** 450

> The streets are quiet, the lights are fading, and one delivery is still waiting to be collected. No sender. No explanation. Just a package marked for tonight.

**Flag:** `safctf{f895fa37be9a374582ff7694a4748862}`

---

## TL;DR

The service exposes an endpoint that happily tells you whether a ciphertext decrypts to valid PKCS#7 padding. That one bit of feedback, repeated a few thousand times, is enough to decrypt the entire ciphertext without ever knowing the key — a classic Vaudenay CBC padding-oracle attack. The recovered plaintext is a "receipt" string, which the service's `/submit` endpoint exchanges for the real flag.

---

## Recon

Service: `http://54.72.82.22:8440` (Flask/Werkzeug). The "Desk console" on the landing page documents the API directly:

```
GET  /api/parcel             -> current parcel ciphertext
POST /api/receipt            -> {"parcel": "<hex>"} records delivery status
```

`GET /api/parcel` (and the provided `parcel.json`) returns a 192-hex-char string — 96 bytes:

```
f989a62eb693b12abd793ff509201480688cd318f1c25ed237a11f60d4205a
8833b10d61c5a53091ba32fb8d86afae986ebbb995cb7abcca4f7f9d50047b6
9be3276bce6e68c835f2e494b283e13c4c1929896ee8533244aeea21df7f16
77c43
```

96 bytes splits cleanly into six 16-byte AES blocks: one IV plus five ciphertext blocks — a strong hint for CBC mode.

### Confirming the oracle

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

`"pending"` only appears when PKCS#7 padding validates; any tamper gives `"damaged"`. That's a full padding oracle: no key or plaintext knowledge needed, just this valid/invalid signal.

## The attack

Standard CBC decryption: `P_i = D(C_i) XOR C_{i-1}` (with `C_0 = IV`). The oracle lets us learn `D(C_i)` ("intermediate" value) one byte at a time, per block, by submitting `(modified C_{i-1}) || C_i` and watching whether the decrypted *last byte(s)* of that pair form valid padding:

1. For block `i`, starting from the last byte (pad length 1) and working backward:
   - Set all already-known suffix bytes of the *previous* block so the target padding value `pad_val` is already satisfied there.
   - Brute-force the remaining unknown byte (0–255) of the modified previous block until the oracle reports valid padding.
   - That guess byte XORed with `pad_val` gives one byte of the AES intermediate value for block `i`.
   - For the very first guess per block (`pad_val = 1`), there's a known ambiguity (the original, unmodified padding may also look "valid"); disambiguate by flipping an earlier byte and re-checking.
2. Once all 16 intermediate bytes for block `i` are known, XOR with the *real* `C_{i-1}` to get the true plaintext block.
3. Repeat for each block from last to first; no decryption key is ever needed.

This requires roughly `5 blocks × 16 bytes × ~128 average guesses ≈ 10,000` oracle queries. Running them with light concurrency (and retry/backoff, since the service didn't like being hit with large bursts) keeps it reliable.

## Script

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

Driving this over all five ciphertext blocks (last to first) and stripping the final PKCS#7 padding recovers:

```
Receipt for the evening delivery: safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}
```

## Redeeming the receipt

As with the earlier challenges, the decrypted string isn't the flag — submitting it to the CTF platform directly fails. It's a receipt the service itself will exchange for the real flag:

```bash
curl -i -X POST http://54.72.82.22:8440/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}"}'
# {"message":"safctf{f895fa37be9a374582ff7694a4748862}","ok":true}
```

(`POST /api/receipt` with the UUID as the `parcel` field just returns `422 {"status":"damaged"}` — that endpoint only accepts hex ciphertext, not the receipt string. `/submit` is the right endpoint, matching the pattern from the other two challenges in this series.)

## Takeaways

- Never let a decrypt-and-validate-padding path leak its result to an attacker-controlled input. This is the textbook Vaudenay/POODLE-class bug: encrypt-then-MAC (or an AEAD mode) with a constant-time, uniform error response removes the oracle entirely.
- A padding oracle requires no knowledge of the key and needs no cryptanalytic breakthrough — just a reliable binary signal repeated enough times.
- Keep the oracle attack itself polite: large request bursts triggered server-side stalls here, so modest concurrency with retries was more reliable than raw speed.
- As with the rest of this challenge series, the decrypted artifact was a "receipt," not the final flag — always check whether the service has a redemption step.

**Flag:** `safctf{f895fa37be9a374582ff7694a4748862}`
