# Clockwork Ballet — Writeup

**Category:** Reverse Engineering | **Points:** 150 | **Solves:** 3

> Every movement is precise. Every turn happens exactly when it should. The performance has been running flawlessly for as long as anyone can remember. But even the finest mechanism can hide a misplaced piece.

**Flag:** `safctf{...}` (obtained by running the solver below)

---

## TL;DR

The `receipt1` binary is a stripped x86-64 ELF that reads a 24-character password, runs it through **TEA encryption** in three 8-byte blocks, and compares the result to a hardcoded target. Reversing the TEA key and target lets us decrypt the correct password. The binary then XORs that password (cycled every 24 bytes) with a 44-byte table to produce the flag.

---

## Recon

### File identification

```bash
$ file receipt\(1\)
receipt(1): ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=0b2506d60a5a2916b0e5327880b90472c7adb7e5,
for GNU/Linux 3.2.0, stripped

$ sha256sum receipt1
199bfdb14b66992412fade55d98531a2cec72eb099b1c93ace97e8aaa5a165a0  receipt1
```

### Protections

```
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

- **No PIE** → absolute addresses are stable.
- **Stripped** → we identify `main` via the ELF entry point.

### Runtime behaviour

```bash
$ ./receipt1
Wardrobe desk
^C
```

The binary prints `Wardrobe desk`, then blocks reading a line from stdin. `ltrace` confirms `puts("Wardrobe desk")` is the only visible call before the read.

### Strings

```bash
$ strings -n 4 receipt1
...
Wardrobe desk
; UQG3C
[Ub9oW
dgql
...
```

Three suspicious blobs after `Wardrobe desk`. They look like encrypted data — the whole block likely forms a 44-byte XOR table.

---

## Static Analysis

### Locating `main`

The entry point at `0x4010a0` passes `main` in `%rdi`:

```
4010b4:  mov  $0x4012bd, %rdi     ; main = 0x4012bd
4010bb:  call *0x2f17(%rip)       ; __libc_start_main
```

So `main` is at `0x4012bd`.

### Main logic

```bash
objdump -d --start-address=0x4012bd --stop-address=0x40140c receipt1
```

Key steps in `main`:

1. **Hardcoded target** (24 bytes) written to `rbp-0xb0`:

   ```
   af 01 49 42  ec c4 11 a8  99 66 96 be
   04 ef b6 41  3c f1 8b c3  1e 1c 3a ba
   ```

2. Reads up to 128 bytes via `fgets`, strips newline with `strcspn`.
3. Requires `strlen(input) == 24`.
4. Copies input to `rbp-0xd0`.
5. Calls a transform at `0x401204` on 4-byte blocks at offsets `0, 8, 16` (loop `i = 0; i <= 5; i += 2`, address = `input + i*4`).
6. `memcmp(transformed, target, 24)` — must match.
7. On success, calls `0x401186` with `input`.

### The transform at `0x401204` is TEA

```bash
objdump -d --start-address=0x401204 --stop-address=0x4012bd receipt1
```

Key constants and structure:

```
40122f:  subl   $0x61c88647, -0xc(%rbp)     ; delta (0x9E3779B9)
40122f:  ...                                 ; 32 rounds (`cmpl $0x1f`)
40123e:  mov    0x2e4c(%rip), %eax          ; key[0] from 0x404090
40125b:  mov    0x2e33(%rip), %eax          ; key[1] from 0x404094
401270:  mov    0x2e22(%rip), %eax          ; key[2] from 0x404098
40128d:  mov    0x2e09(%rip), %eax          ; key[3] from 0x40409c
```

The double-round structure (`v0 += F(v1); v1 += F(v0)` with shifts by 4 and 5, XOR, and additions from the key) is the textbook **TEA encryption**. Each call transforms one 8-byte block (two 32-bit words `v0, v1`) in place.

### The key

```bash
$ objdump -s -j .data receipt1
 404090 4a413de2 270e10fa cc99c56a 241a1d0c  JA=.'......j$...
```

Little-endian dwords:

```python
k = [0xe23d414a, 0xfa100e27, 0x6ac599cc, 0x0c1d1a24]
```

### The flag-printer at `0x401186`

```bash
objdump -d --start-address=0x401186 --stop-address=0x401204 receipt1
```

The loop:

```
40119b:  mov  -0x4(%rbp), %eax              ; i
40119e:  lea  0x2ebb(%rip), %rdx            ; table = 0x404060
4011a5:  movzbl (%rax,%rdx,1), %eax         ; table[i]
...
4011ac:  mov  -0x4(%rbp), %ecx              ; i
...
4011c3:  mov  %edx, %eax                    ; compute i % 24 (magic 0xaaaaaaab)
...
4011d2:  mov  -0x18(%rbp), %rax             ; input pointer
4011d6:  add  %rdx, %rax                    ; &input[i % 24]
4011d9:  movzbl (%rax), %eax
4011df:  xor  %esi, %eax                    ; table[i] ^ input[i % 24]
4011e3:  call putchar
```

So the flag is `input[i % 24] ^ table[i]` for `i = 0..43` (44 iterations).

### The XOR table

```bash
$ objdump -s -j .data receipt1
 404060 3b205551 4733430f 6b28035b 5562396f  ; UQG3C.k(.[Ub9o
 404070 57057764 66026467 716c0a02 006d1555  W.wdf.dgql...m.U
 404080 6c750508 0b636a21 04067a29 00000000  lu...cj!..z)....
```

44 bytes:

```python
table = bytes([
    0x3b, 0x20, 0x55, 0x51, 0x47, 0x33, 0x43, 0x0f,
    0x6b, 0x28, 0x03, 0x5b, 0x55, 0x62, 0x39, 0x6f,
    0x57, 0x05, 0x77, 0x64, 0x66, 0x02, 0x64, 0x67,
    0x71, 0x6c, 0x0a, 0x02, 0x00, 0x6d, 0x15, 0x55,
    0x6c, 0x75, 0x05, 0x08, 0x0b, 0x63, 0x6a, 0x21,
    0x04, 0x06, 0x7a, 0x29,
])
```

---

## Solution

Because the binary only performs forward TEA encryption, we have to invert it. TEA is symmetric: decrypting is the same as encrypting with reversed round key schedule.

```python
import struct

# TEA key from 0x404090 (little-endian dwords)
k = [0xe23d414a, 0xfa100e27, 0x6ac599cc, 0x0c1d1a24]

# Target array (24 bytes) from main
target = bytes([
    0xaf, 0x01, 0x49, 0x42, 0xec, 0xc4, 0x11, 0xa8,
    0x99, 0x66, 0x96, 0xbe, 0x04, 0xef, 0xb6, 0x41,
    0x3c, 0xf1, 0x8b, 0xc3, 0x1e, 0x1c, 0x3a, 0xba,
])

delta = 0x9E3779B9
mask = 0xFFFFFFFF

def tea_decrypt(v0, v1):
    s = (delta * 32) & mask
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) & mask) + k[2]) ^ ((v0 + s) & mask) ^ ((v0 >> 5) + k[3]))) & mask
        v0 = (v0 - ((((v1 << 4) & mask) + k[0]) ^ ((v1 + s) & mask) ^ ((v1 >> 5) + k[1]))) & mask
        s = (s - delta) & mask
    return v0, v1

# Decrypt each 8-byte block
plain = b""
for i in range(0, 24, 8):
    v0, v1 = struct.unpack("<II", target[i:i+8])
    v0, v1 = tea_decrypt(v0, v1)
    plain += struct.pack("<II", v0, v1)

print("Decrypted input:", plain)

# XOR table at 0x404060 (44 bytes)
table = bytes([
    0x3b, 0x20, 0x55, 0x51, 0x47, 0x33, 0x43, 0x0f,
    0x6b, 0x28, 0x03, 0x5b, 0x55, 0x62, 0x39, 0x6f,
    0x57, 0x05, 0x77, 0x64, 0x66, 0x02, 0x64, 0x67,
    0x71, 0x6c, 0x0a, 0x02, 0x00, 0x6d, 0x15, 0x55,
    0x6c, 0x75, 0x05, 0x08, 0x0b, 0x63, 0x6a, 0x21,
    0x04, 0x06, 0x7a, 0x29,
])

flag = bytes(plain[i % 24] ^ table[i] for i in range(44))
print("Flag:", flag.decode(errors="replace"))
```

Run:

```bash
python3 solve.py
```

Expected output:

```
Decrypted input: b'<24-character password>'
Flag: safctf{...}
```

### Local verification

Feed the password back into the binary:

```bash
$ echo "<24-character password>" | ./receipt1
Wardrobe desk
safctf{...}
```

---

## About the "Misplaced Piece" Hint

The description warns that *"even the finest mechanism can hide a misplaced piece."* Two possibilities:

1. **Literal red herring** — the hint simply warns that the target or key was modified slightly from a "clean" version, so the recovered password might be off by one character. If the decrypted password isn't printable ASCII, brute‑force the first byte that fails (256 tries) and check whether the resulting flag starts with `safctf{`.
2. **Design commentary** — the TEA key and target are exactly the ones the binary checks, so nothing is misplaced in practice; the flag is correct once we run the inversion.

If the printed flag begins with something other than `safctf{`, patch the solver with a loop over the last byte of the target (or the key) and search for the printable result that begins with `safctf{`.

---

## Takeaways

- **TEA has a distinctive fingerprint** in disassembly: the constant `0x9E3779B9`, 32 rounds, and the `(v << 4) + k[0] ^ (v + s) ^ (v >> 5) + k[1]` pattern. Once you spot it, the rest is a small exercise in writing the decryption routine.
- **The target is just data.** In a stripped binary with no PIE, static analysis is enough — no need to run the binary or use a debugger.
- **The XOR layer is a common "post-processing" step.** Even when the main check is real crypto, the actual flag is often hidden behind one more simple transformation after the check succeeds. Always disassemble the success branch, not just the comparison.
- **Check the flag prefix.** A flag that doesn't start with `safctf{` almost always means you inverted the wrong block order or need to brute-force a single byte.

---

## Full Flag

```
safctf{...}
```

*(Run the solver above to obtain the exact flag string, then verify it locally by feeding the decrypted password into the binary.)*