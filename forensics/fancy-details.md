# Fancy Details — Writeup

**Category:** Forensics | **Points:** 300

> The afternoon crowd is still singing.
> The final whistle has blown, the stands are emptying, and the replay system is quietly preserving every moment. But somewhere among the archived sessions, one detail doesn't quite belong.
> A thoughtful touch can change the whole impression.
> The replay may be finished, but the story isn't.
> Dig through the details. Find what doesn't belong. And recover what was left behind.

**Flag:** `safctf{245ccf0110f6422d41671064cee8da68}`

---

## TL;DR

The real secret was hiding in plain sight in a JPEG's EXIF `Artist` tag, obfuscated with ROT13 + string reversal. That gave the passphrase for an `openssl enc`-encrypted archive, whose cipher and KDF parameters weren't labeled and had to be brute-forced. Unwrapping it peeled back two more layers of tar archive before reaching `flag.txt`.

---

## Recon

Service: `http://54.72.82.22:8210` ("FRAME / FOUND" — a fake travel-photography site). Two resources on the landing page:

- `/downloads/photo.jpg` — a 1024×1024 JPEG
- `/downloads/archive.tar.gz.enc` — flagged by `file` as `openssl enc'd data with salted password` (the standard `Salted__` header)

```bash
exiftool -a -u -g1 photo.jpg
```

```
[IFD0]  Artist          : qebjffnc
[GPS]   GPSLatitude     : 52 deg 28' 48.00"
[GPS]   GPSLongitude    : 1 deg 53' 24.00"
```

No other interesting EXIF/XMP/IPTC fields, no PNG-style text chunks (it's a JPEG), no trailing data after the `FFD9` end-of-image marker, and `steghide`/`stegseek` against the image (with rockyou and a custom wordlist) turned up nothing — that path and the GPS coordinates were both red herrings. The image's decorative "data" numerals in the background art were likewise just AI-image-generation artifacts, not an encoded value (inconsistent glyph shapes, no stable digit count — a classic diffusion-model text-rendering failure, not a deliberate puzzle).

## The real clue: "a thoughtful touch can change the whole impression"

`Artist` is a deliberately apt field for this hint — literally "whoever touched/authored this." Decoding `qebjffnc`:

```python
import codecs
s = "qebjffnc"
codecs.encode(s, "rot13")        # -> 'drowssap'
codecs.encode(s, "rot13")[::-1]  # -> 'password'
```

ROT13 then reverse (order doesn't matter — they commute) gives the plaintext `password`.

## Decrypting the archive

`archive_tar_gz.enc` only tells us it's `openssl enc` output via the `Salted__` magic bytes; the cipher, digest, and iteration count aren't stored in the file and have to be guessed. A plain:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in archive_tar_gz.enc -out archive.tar.gz -k password
```

fails ("bad decrypt"). Because OpenSSL's CBC mode validates PKCS#7 padding, any wrong password/cipher/KDF combo reliably errors out — but a *wrong* combo can occasionally still pass the padding check by chance and produce garbage that looks like a "success." The fix is to also check the decrypted output actually starts with gzip's magic bytes (`1f 8b`), not just that `openssl` exited cleanly.

A small brute force over common AES variants, digests, and iteration counts nailed it:

```python
import subprocess
ciphers = ["aes-256-cbc","aes-192-cbc","aes-128-cbc","des-ede3-cbc","bf-cbc","cast5-cbc"]
mds     = ["md5","sha1","sha256","sha512"]
iters   = [1,1000,10000,100000,200000]

for c in ciphers:
    for it in iters:
        for md in mds:
            r = subprocess.run(
                ["openssl","enc","-d",f"-{c}","-pbkdf2","-iter",str(it),"-md",md,
                 "-in","archive_tar_gz.enc","-out","/tmp/o.bin","-k","password"],
                capture_output=True)
            if r.returncode == 0 and open("/tmp/o.bin","rb").read(2) == b"\x1f\x8b":
                print("HIT", c, md, it)
```

Result: **`aes-256-cbc`, PBKDF2, `-md sha256`, `-iter 100000`**.

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 \
  -in archive_tar_gz.enc -out archive.tar.gz -k password
```

## Peeling the layers

```
archive.tar.gz   (gzip)
  └── nested1.tar
        └── flag.txt
```

```bash
tar xzf archive.tar.gz        # -> nested1.tar
tar xf  nested1.tar           # -> flag.txt
cat flag.txt
```

```
safctf{245ccf0110f6422d41671064cee8da68}
```

## Takeaways

- EXIF `Artist`/`Comment`/`Copyright` fields are an easy, low-effort hiding spot for CTF steganography — always dump full metadata with `exiftool -a -u -g1` before anything fancier.
- A field that looks like meaningless noise is worth a quick ROT13 and a reversal check; these are two of the cheapest transforms to brute-force by hand.
- `openssl enc`'s `Salted__` header carries no indication of cipher, digest, or iteration count. When password-cracking such a file, validate success by checking the *decrypted content's* magic bytes, not just OpenSSL's exit code — wrong guesses can still pass PKCS#7 padding validation by chance.
- Don't over-read flavor/decorative elements (background "data" numerals, GPS coordinates) as puzzle content just because they're visually present — verify they're internally consistent and tie back to something concrete before spending time on them.

**Flag:** `safctf{245ccf0110f6422d41671064cee8da68}`
