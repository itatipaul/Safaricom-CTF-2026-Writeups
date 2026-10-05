# Three Encores — Writeup

**Category:** Crypto (RSA) | **Points:** 300 | **Solves:** 34

> A familiar melody in three different rooms.
> An old key ledger claims a value was reused; it may describe a different dispatch.

**Flag:** `safctf{0471ad15e84bb9f630e394e49dde85a9}`

---

## TL;DR

Three RSA "deliveries" with `e = 3`, three different moduli and the **same ciphertext** `c`. Because the ciphertext is identical, Håstad's broadcast attack collapses to a plain integer cube root of `c`. The plaintext is `programme:safctf{dadb56ae-...}`. Submitting the *inner* `safctf{...}` string to the service's `/submit` endpoint returns the real flag.

---

## Recon

The challenge web service (`http://54.72.82.22:8420`) is a small Flask/Werkzeug app:

- `GET /` — landing page with a single download, `/downloads/programme.json`
- `POST /submit` — accepts JSON `{"answer": "..."}` (found in the page's inline JS; `GET` returns 405)
- Page text hints: *"Keep your collection receipt when your visit is complete."*

`programme.json` is static (same SHA-256 on every download, no cookies/headers of note):

```json
{"deliveries": [
  {"n": "0x600d...", "e": 3, "c": "0x15b1..."},
  {"n": "0xb3e7...", "e": 3, "c": "0x15b1..."},
  {"n": "0x8069...", "e": 3, "c": "0x15b1..."}
]}
```

Observations:

- `e = 3` in all three entries.
- Moduli are ~1536 bits and pairwise coprime (`gcd = 1`), so no shared-factor shortcut.
- `c` is **identical** across all three entries and smaller than every `n`.

## Vulnerability

"Three rooms, same melody" is a Håstad broadcast setup: one message `m` encrypted with `e = 3` under three moduli, no padding. Normally the three ciphertexts differ, and you recover `m³` with CRT.

Here the ciphertexts are the same, which makes it even simpler:

```
m³ ≡ c (mod n1), (mod n2), (mod n3)
⇒ m³ ≡ c (mod n1·n2·n3)      (CRT, moduli coprime)
```

Since `m < min(n_i)`, we have `m³ < n1·n2·n3`, so reducing modulo the product does not wrap: `m³ = c` exactly over the integers, i.e. `m = ∛c`.

## Solution

```python
c = 0x15b1f932...   # shared ciphertext from programme.json

def icbrt(x):
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < x: lo = mid + 1
        else:          hi = mid
    return lo

m = icbrt(c)
assert m**3 == c            # exact cube -> confirms the attack
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
```

Output:

```
b'programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}'
```

## The twist

Pasting that flag into the CTF platform was **rejected**. The `programme:` prefix is a label, and the UUID flag is a decoy "ledger" value — the hint ("*may describe a different dispatch*") was telling us the data in `programme.json` is not the final flag, but the key to the service.

Submitting to the service:

```bash
# full plaintext -> 403
curl -i -X POST http://54.72.82.22:8420/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"}'
# {"message":"The request could not be completed.","ok":false}

# inner string only -> 200
curl -i -X POST http://54.72.82.22:8420/submit \
  -H 'Content-Type: application/json' \
  -d '{"answer":"safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"}'
# {"message":"safctf{0471ad15e84bb9f630e394e49dde85a9}","ok":true}
```

The service's response is the "collection receipt" — the real flag.

## Takeaways

- Identical ciphertexts under different moduli with a small `e` and no padding reduce to an integer root; always test `∛c` (or `e`-th root) first.
- Always sanity-check by verifying `m**e == c` exactly.
- When a decrypted flag is rejected, read the challenge text again — here, the web service was part of the puzzle, not just a file host. Probe the endpoints the frontend JS references.
- Real-world lesson: textbook RSA with a tiny exponent and no padding (OAEP) is insecure.

**Flag:** `safctf{0471ad15e84bb9f630e394e49dde85a9}`
