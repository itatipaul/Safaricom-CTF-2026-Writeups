# Clockwork Ballet — Reverse Engineering Writeup

**Challenge:** Clockwork Ballet (150 pts)
**Category:** Reverse Engineering
**Target:** `http://54.72.82.22:8520`
**Artifact:** `receipt` — ELF 64-bit LSB executable, x86-64, dynamically linked, **stripped** (14,536 bytes)
**Flag:** `safctf{93d4bf6a-b750-4379-9038-c4921872c148}`

---

## 1. TL;DR

The `receipt` binary is a license/serial checker:

1. Reads a line, requires the trimmed length to be **exactly 24 characters**.
2. Copies those 24 bytes onto the stack and **TEA-encrypts** them in place (three 8-byte blocks, 32 rounds, delta `0x9e3779b9`).
3. `memcmp`s the ciphertext against six hard-coded dwords baked into `main`.
4. On a match, calls a printer that emits 44 bytes of `input[i % 24] ^ table[i]`.

The required serial is the **TEA decryption of the hard-coded target block**, and the printer output is the flag:

```
serial : HA323U86XL793TXB52BTK6WP
flag   : safctf{93d4bf6a-b750-4379-9038-c4921872c148}
```

Verified by running the binary locally: the recovered serial exits `0` and prints the flag; a wrong serial exits `1`.

---

## 2. Recon

### 2.1 The web service

```
$ curl -s -i http://54.72.82.22:8520/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 3571
```

The landing page is a static "Collection desk" with a single download link:

```html
<a class="download" href="/downloads/receipt">receipt</a>
```

It also ships inline JavaScript that references a form (`#answer`, `#out`, and a `console`
mode with `#path`/`#method`/`#headers`/`#body`) — but **the page contains no `<form>` element
at all**. That JS is dead template code (this CTF reuses a common front-end across challenges).
GET `/submit` returns `405 (Allow: POST, OPTIONS)`); POST `/submit` returns a uniform
`403 {"message":"The request could not be completed.","ok":false}` for *every* body, including
malformed JSON. It is not the authoritative checker for this instance — the flag comes from the
artifact itself.

Other probe results:

| Path | Result |
|---|---|
| `/` | 200, static HTML |
| `/health` | 200 `{"status":"ok"}` |
| `/downloads/receipt` | 200, the ELF binary |
| `/submit` | POST → uniform 403; GET → 405 |
| `/api/*` | blueprint catch-all `404 {"message":"Not found"}` |
| everything else | 404 |

### 2.2 The artifact

```
$ curl -s -o receipt http://54.72.82.22:8520/downloads/receipt
$ file receipt
receipt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
         interpreter /lib64/ld-linux-x86-64.so.2,
         BuildID[sha1]=0b2506d60a5a2916b0e5327880b90472c7adb7e5,
         for GNU/Linux 3.2.0, stripped

sha256: 199bfdb14b66992412fade55d98531a2cec72eb099b1c93ace97e8aaa5a165a0
```

The binary is tiny — `.text` is only `0x36c` (876) bytes — so it can be read in full.

---

## 3. Static analysis

### 3.1 Imports and strings

```
$ strings -a -n 5 receipt
...
fgets
stdin
putchar
strlen
strcspn
__libc_start_main
memcmp
memcpy
libc.so.6
Wardrobe desk
```

The import set is the whole story: `fgets` reads a line, `strlen`/`strcspn` trim and measure it,
`memcpy` stages it, `memcmp` compares it, `putchar` emits the result. There is **no crypto
library** — the cipher is hand-rolled in the binary.

### 3.2 Sections

```
[13] .text     PROGBITS  00000000004010a0  000010a0  00036c  AX
[15] .rodata   PROGBITS  0000000000402000  00002000  000015  A
[24] .data     PROGBITS  0000000000404040  00003040  000060  WA
```

Entry point `0x4010a0`. `__libc_start_main` is called with `rdi = 0x4012bd`, so **`main` is at
`0x4012bd`**.

### 3.3 The three functions that matter

The stripped binary still separates cleanly into three routines:

| Address | Role |
|---|---|
| `0x4012bd` | `main` — read, encrypt, compare, print |
| `0x401204` | TEA **encrypt** of one 8-byte block |
| `0x401186` | printer — 44-byte XOR stream |

(`0x4010e0`, `0x401110`, `0x401150` are the usual `__do_global_dtors_aux` / `frame_dummy` /
`register_tm_clones` boilerplate.)

---

## 4. `main` @ `0x4012bd`

### 4.1 The target constants

```asm
4012c8:  mov DWORD PTR [rbp-0xb0], 0x424901af
4012d2:  mov DWORD PTR [rbp-0xac], 0xa811c4ec
4012dc:  mov DWORD PTR [rbp-0xa8], 0xbe966699
4012e6:  mov DWORD PTR [rbp-0xa4], 0x41b6ef04
4012f0:  mov DWORD PTR [rbp-0xa0], 0xc38bf13c
4012fa:  mov DWORD PTR [rbp-0x9c], 0xba3a1c1e
```

Six dwords = **24 bytes** of expected ciphertext, stored little-endian at `[rbp-0xb0]`.

### 4.2 Read + validate

```asm
401304:  lea    rax,[rip+0xcfa]           # 402005  "Wardrobe desk"
40130e:  call   puts
401313:  mov    rdx,QWORD PTR [rip+0x2d86] # 4040a0  stdin
40131a:  lea    rax,[rbp-0x90]
401321:  mov    esi,0x80                  # fgets(buf, 128, stdin)
401329:  call   fgets
40132e:  test   rax,rax
401331:  jne    40133d
401333:  mov    eax,0x1                   # EOF -> exit 1
401338:  jmp    40140a

40133d:  lea    rax,[rbp-0x90]
401344:  lea    rdx,[rip+0xcc8]           # 402013  "\n"
401351:  call   strcspn                   # index of newline
401356:  mov    BYTE PTR [rbp+rax*1-0x90],0x0   # strip it

401365:  call   strlen
40136d:  cmp    rax,0x18                  # strlen == 24 ?
401371:  je     40137d
401373:  mov    eax,0x1                   # wrong length -> exit 1
```

> Note the `+0xcc8` reference resolves to `0x402013`, which is the byte `0x0a` followed by
> `0x00` — i.e. the string `"\n"`. (`0x402012` is the NUL that terminates `"Wardrobe desk"`.)
> So the newline *is* correctly stripped.

**Constraint: the serial is exactly 24 characters.**

### 4.3 Encrypt in place

```asm
40137d:  lea    rcx,[rbp-0x90]            # src = input
401384:  lea    rax,[rbp-0xd0]            # dst = scratch
40138b:  mov    edx,0x18                  # 24 bytes
401396:  call   memcpy

40139b:  mov    DWORD PTR [rbp-0x4],0x0   # i = 0
4013a2:  jmp    4013c7
4013a4:  mov    eax,[rbp-0x4]             # i
4013a9:  lea    rdx,[rax*4]               # offset = i*4
4013b8:  add    rax,rdx                   # &scratch[i*4]
4013be:  call   401204                    # TEA-encrypt 8 bytes in place
4013c3:  add    DWORD PTR [rbp-0x4],0x2   # i += 2   ->  i = 0,2,4
4013c7:  cmp    DWORD PTR [rbp-0x4],0x5
4013cb:  jle    4013a4
```

`i` steps `0, 2, 4`; each step handles `i*4` bytes = `0, 8, 16`. **Three 8-byte blocks cover all 24 bytes.**

### 4.4 Compare + print

```asm
4013cd:  lea    rcx,[rbp-0xb0]            # expected ciphertext
4013d4:  lea    rax,[rbp-0xd0]            # our ciphertext
4013db:  mov    edx,0x18
4013e6:  call   memcmp                    # memcmp(ours, expected, 24)
4013eb:  test   eax,eax
4013ed:  je     4013f6
4013ef:  mov    eax,0x1                   # mismatch -> exit 1
4013f4:  jmp    40140a

4013f6:  lea    rax,[rbp-0x90]            # rdi = ORIGINAL input (still plaintext!)
401400:  call   401186                    # print the receipt
401405:  mov    eax,0x0                   # exit 0
```

So the flow is **encrypt-then-compare**: to pass, our plaintext must be the TEA *decryption* of
the baked-in target. On success the *original plaintext* is handed to the printer.

---

## 5. TEA encryptor @ `0x401204`

```asm
401204:  push   rbp
401208:  mov    QWORD PTR [rbp-0x18],rdi    ; v = pointer to 8 bytes
401210:  mov    eax,DWORD PTR [rax]         ; v0 = v[0]
401212:  mov    DWORD PTR [rbp-0x4],eax
401219:  mov    eax,DWORD PTR [rax+0x4]     ; v1 = v[1]
40121c:  mov    DWORD PTR [rbp-0x8],eax
40121f:  mov    DWORD PTR [rbp-0xc],0x0     ; sum = 0
401226:  mov    DWORD PTR [rbp-0x10],0x0    ; i = 0
40122d:  jmp    40129e

40122f:  sub    DWORD PTR [rbp-0xc],0x61c88647   ; sum += 0x9e3779b9  (== -0x61c88647)

401236:  mov    eax,[rbp-0x8]               ; v1
401239:  shl    eax,0x4
40123e:  mov    eax,[rip+0x2e4c]            ; k0  @ 0x404090
401244:  lea    ecx,[rdx+rax]               ; (v1<<4) + k0
40124a:  mov    eax,[rbp-0xc]               ; sum
40124d:  add    eax,edx                     ; sum + v1
40124f:  xor    ecx,eax
401256:  shr    eax,0x5                     ; v1>>5
40125b:  mov    eax,[rip+0x2e33]            ; k1  @ 0x404094
401261:  add    eax,ecx
401263:  xor    eax,edx
401265:  add    DWORD PTR [rbp-0x4],eax     ; v0 += ((v1<<4)+k0) ^ (sum+v1) ^ ((v1>>5)+k1)

401268:  mov    eax,[rbp-0x4]               ; v0
40126b:  shl    eax,0x4
401270:  mov    eax,[rip+0x2e22]            ; k2  @ 0x404098
401276:  lea    ecx,[rdx+rax]               ; (v0<<4) + k2
40127c:  mov    eax,[rbp-0xc]               ; sum
40127f:  add    eax,edx                     ; sum + v0
401281:  xor    ecx,eax
401288:  shr    eax,0x5                     ; v0>>5
40128d:  mov    eax,[rip+0x2e09]            ; k3  @ 0x40409c
401293:  add    eax,ecx
401295:  xor    eax,edx
401297:  add    DWORD PTR [rbp-0x8],eax     ; v1 += ((v0<<4)+k2) ^ (sum+v0) ^ ((v0>>5)+k3)

40129a:  add    DWORD PTR [rbp-0x10],0x1    ; i++
40129e:  cmp    DWORD PTR [rbp-0x10],0x1f   ; 32 rounds
4012a2:  jle    40122f
```

This is textbook **TEA encryption** — `sum` starts at 0, each of the 32 rounds adds
`delta = 0x9e3779b9`, then updates `v0` then `v1`. All arithmetic is mod 2³².

```
sum = 0
for i in 0..31:
    sum += 0x9E3779B9
    v0 += ((v1 << 4) + k0) ^ (sum + v1) ^ ((v1 >> 5) + k1)
    v1 += ((v0 << 4) + k2) ^ (sum + v0) ^ ((v0 >> 5) + k3)
```

The function is used as an *encryptor*, so we invert it to recover the serial.

---

## 6. Printer @ `0x401186`

```asm
40118e:  mov    QWORD PTR [rbp-0x18],rdi    ; rdi = 24-char plaintext
401192:  mov    DWORD PTR [rbp-0x4],0x0     ; i = 0
401199:  jmp    4011ec

40119b:  mov    eax,DWORD PTR [rbp-0x4]     ; i
40119e:  lea    rdx,[rip+0x2ebb]            ; table @ 0x404060
4011a5:  movzx  eax,BYTE PTR [rax+rdx*1]    ; table[i]
4011a9:  movzx  esi,al

4011af:  mov    edx,ecx                     ; i
4011b1:  mov    eax,0xaaaaaaab              ; magic for /24
4011b6:  imul   rax,rdx
4011ba:  shr    rax,0x20
4011c0:  shr    edx,0x4
4011c5:  add    eax,eax
4011c7:  add    eax,edx
4011c9:  shl    eax,0x3                     ; edx = i/24
4011cc:  sub    ecx,eax                     ; ecx = i - 24*(i/24) = i % 24

4011d2:  mov    rax,[rbp-0x18]              ; input
4011d6:  add    rax,rdx
4011d9:  movzx  eax,BYTE PTR [rax]          ; input[i % 24]
4011df:  xor    eax,esi
4011e3:  call   putchar

4011e8:  add    DWORD PTR [rbp-0x4],0x1     ; i++
4011ec:  cmp    DWORD PTR [rbp-0x4],0x2b    ; 44 iterations
4011f0:  jbe    40119b

4011f2:  lea    rax,[rip+0xe0b]             # 402004  "" -> newline
4011fc:  call   puts
```

The `0xaaaaaaab` magic with `shr 32` / `shr 4` is the compiler's unsigned division by 24;
`ecx = i % 24`. So the printer emits exactly 44 bytes:

```
out[i] = input[i % 24] ^ table[i]      for i = 0..43
```

44 bytes is precisely the length of a `safctf{...}` flag string — that's the design intent:
the 24-char serial seeds a repeating key stream that reconstructs the 44-char flag.

---

## 7. Data extraction

### 7.1 `.rodata` @ `0x402000` (21 bytes)

```
402000  01 00 02 00  00 57 61 72 64 72 6f 62 65 20 64 65   .....Wardrobe de
402010  73 6b 00 0a 00                                       sk...
```

| Address | Content | Use |
|---|---|---|
| `0x402004` | `""` | `puts` → newline after the flag |
| `0x402005` | `"Wardrobe desk"` | banner |
| `0x402013` | `"\n"` | `strcspn` reject set (newline strip) |

### 7.2 `.data` @ `0x404040` (96 bytes)

```
404040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
404050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
404060  3b 20 55 51 47 33 43 0f 6b 28 03 5b 55 62 39 6f   ; UQG3C.k(.[Ub9o
404070  57 05 77 64 66 02 64 67 71 6c 0a 02 00 6d 15 55   W.wdf.dgql...m.U
404080  6c 75 05 08 0b 63 6a 21 04 06 7a 29 00 00 00 00   lu...cj!..z)....
404090  4a 41 3d e2 27 0e 10 fa cc 99 c5 6a 24 1a 1d 0c   JA=.'......j$...
```

| Address | Size | Content |
|---|---|---|
| `0x404040` | 32 B | zero padding |
| `0x404060` | **44 B** | XOR key stream used by the printer |
| `0x404090` | **16 B** | TEA key (4 × u32 LE) |

TEA key as little-endian dwords:

```
k0 = 0xE23D414A   (bytes 4a 41 3d e2)
k1 = 0xFA100E27   (bytes 27 0e 10 fa)
k2 = 0x6AC599CC   (bytes cc 99 c5 6a)
k3 = 0x0C1D1A24   (bytes 24 1a 1d 0c)
```

Printer table (44 bytes, hex):

```
3b2055514733430f6b28035b5562396f
5705776466026467716c0a02006d1555
6c7505080b636a2104067a29
```

---

## 8. Solver

```python
#!/usr/bin/env python3
"""Clockwork Ballet - solver"""

M = 0xFFFFFFFF
DELTA = 0x9E3779B9

# TEA key, 4 x u32 little-endian from .data @ 0x404090
KEY = [0xE23D414A, 0xFA100E27, 0x6AC599CC, 0x0C1D1A24]

# Target ciphertext: 6 dwords @ rbp-0xb0 (main @ 0x4012c8)
TARGET = [
    (0x424901AF, 0xA811C4EC),   # block 0
    (0xBE966699, 0x41B6EF04),   # block 1
    (0xC38BF13C, 0xBA3A1C1E),   # block 2
]

# 44-byte XOR table @ .data 0x404060
TABLE = bytes.fromhex(
    "3b2055514733430f6b28035b5562396f"
    "5705776466026467716c0a02006d1555"
    "6c7505080b636a2104067a29"
)

def tea_decrypt(v0, v1, key):
    k0, k1, k2, k3 = key
    s = (DELTA * 32) & M
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k2) & M) ^ ((s + v0) & M) ^ ((v0 >> 5) + k3))) & M
        v0 = (v0 - ((((v1 << 4) + k0) & M) ^ ((s + v1) & M) ^ ((v1 >> 5) + k1))) & M
        s = (s - DELTA) & M
    return v0, v1

plain = b""
for (a, b) in TARGET:
    v0, v1 = tea_decrypt(a, b, KEY)
    plain += v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

token = bytes((plain[i % 24] ^ TABLE[i]) & 0xFF for i in range(44))
print("serial:", plain.decode())
print("flag  :", token.decode())
```

Output:

```
serial: HA323U86XL793TXB52BTK6WP
flag  : safctf{93d4bf6a-b750-4379-9038-c4921872c148}
```

The solver also asserts the forward direction round-trips back to the baked-in constants, which
is a self-check that the key/endianness/round count are all correct.

---

## 9. Verification

Running the original binary with the recovered serial:

```console
$ printf 'HA323U86XL793TXB52BTK6WP\n' | ./receipt
Wardrobe desk
safctf{93d4bf6a-b750-4379-9038-c4921872c148}
$ echo $?
0
```

Control run with a wrong serial:

```console
$ printf 'AAAAAAAAAAAAAAAAAAAAAAAA\n' | ./receipt
Wardrobe desk
$ echo $?
1
```

The binary accepts only the recovered serial and prints the flag — independent confirmation that
the reversal is correct.

### Flag

```
safctf{93d4bf6a-b750-4379-9038-c4921872c148}
```

---

## 10. Notes for the reader

- **Why "encrypt" instead of "decrypt"?** Many TEA checkers decrypt the user's input and compare
  to a stored plaintext. This one does the opposite — it *encrypts* the input and compares to a
  stored ciphertext. Same work, mirrored. If you had assumed decryption you would have gotten
  garbage out of `memcmp`; reading which direction `sum` runs (`0 → 32·Δ` = encrypt,
  `32·Δ → 0` = decrypt) settles it instantly.
- **The magic constant `0xaaaaaaab`** at `0x4011b1` is not crypto — it is the compiler's
  strength-reduced unsigned division by 24. `ecx` ends up as `i % 24`, i.e. the 24-char serial is
  used as a *repeating* key stream to mask 44 bytes of table.
- **Length arithmetic is a hint.** `strlen == 0x18` (24) on input and 44 (`0x2b + 1`) iterations on
  output; 44 is exactly the length of a `safctf{...}` UUID-form flag, so the intended answer falls
  out of the printer.
- **The `/submit` endpoint is a red herring on this instance.** It returns an identical
  `403 {"message":"The request could not be completed.","ok":false}` for every input, including
  malformed JSON and the correct flag, and the landing page ships a form-handling script with no
  form to handle. The authoritative output here is the artifact's own print.
- **The "misplaced piece" flavour text** ("even the finest mechanism can hide a misplaced piece")
  points at the fact that the artifact, not the web UI, holds the answer — the binary's `main`
  carries the target ciphertext and a `puts("")`-only success path.

---

## Appendix A — Raw `main` disassembly

```asm
00000000004012bd <main>:
  4012bd: push   rbp
  4012be: mov    rbp,rsp
  4012c1: sub    rsp,0xd0
  4012c8: mov    DWORD PTR [rbp-0xb0],0x424901af
  4012d2: mov    DWORD PTR [rbp-0xac],0xa811c4ec
  4012dc: mov    DWORD PTR [rbp-0xa8],0xbe966699
  4012e6: mov    DWORD PTR [rbp-0xa4],0x41b6ef04
  4012f0: mov    DWORD PTR [rbp-0xa0],0xc38bf13c
  4012fa: mov    DWORD PTR [rbp-0x9c],0xba3a1c1e
  401304: lea    rax,[rip+0xcfa]        # 402005
  40130b: mov    rdi,rax
  40130e: call   401040 <puts@plt>
  401313: mov    rdx,QWORD PTR [rip+0x2d86] # 4040a0 <stdin>
  40131a: lea    rax,[rbp-0x90]
  401321: mov    esi,0x80
  401326: mov    rdi,rax
  401329: call   401080 <fgets@plt>
  40132e: test   rax,rax
  401331: jne    40133d
  401333: mov    eax,0x1
  401338: jmp    40140a
  40133d: lea    rax,[rbp-0x90]
  401344: lea    rdx,[rip+0xcc8]        # 402013
  40134b: mov    rsi,rdx
  40134e: mov    rdi,rax
  401351: call   401060 <strcspn@plt>
  401356: mov    BYTE PTR [rbp+rax*1-0x90],0x0
  40135e: lea    rax,[rbp-0x90]
  401365: mov    rdi,rax
  401368: call   401050 <strlen@plt>
  40136d: cmp    rax,0x18
  401371: je     40137d
  401373: mov    eax,0x1
  401378: jmp    40140a
  40137d: lea    rcx,[rbp-0x90]
  401384: lea    rax,[rbp-0xd0]
  40138b: mov    edx,0x18
  401390: mov    rsi,rcx
  401393: mov    rdi,rax
  401396: call   401090 <memcpy@plt>
  40139b: mov    DWORD PTR [rbp-0x4],0x0
  4013a2: jmp    4013c7
  4013a4: mov    eax,DWORD PTR [rbp-0x4]
  4013a7: cdqe
  4013a9: lea    rdx,[rax*4+0x0]
  4013b1: lea    rax,[rbp-0xd0]
  4013b8: add    rax,rdx
  4013bb: mov    rdi,rax
  4013be: call   401204
  4013c3: add    DWORD PTR [rbp-0x4],0x2
  4013c7: cmp    DWORD PTR [rbp-0x4],0x5
  4013cb: jle    4013a4
  4013cd: lea    rcx,[rbp-0xb0]
  4013d4: lea    rax,[rbp-0xd0]
  4013db: mov    edx,0x18
  4013e0: mov    rsi,rcx
  4013e3: mov    rdi,rax
  4013e6: call   401070 <memcmp@plt>
  4013eb: test   eax,eax
  4013ed: je     4013f6
  4013ef: mov    eax,0x1
  4013f4: jmp    40140a
  4013f6: lea    rax,[rbp-0x90]
  4013fd: mov    rdi,rax
  401400: call   401186
  401405: mov    eax,0x0
  40140a: leave
  40140b: ret
```

## Appendix B — Reproduction checklist

```bash
mkdir -p clockwork && cd clockwork
curl -s -o receipt http://54.72.82.22:8520/downloads/receipt
chmod +x receipt
python3 solver.py                     # -> serial + flag
printf 'HA323U86XL793TXB52BTK6WP\n' | ./receipt   # -> flag, exit 0
```
