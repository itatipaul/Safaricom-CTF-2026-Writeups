# Pixel Courier — Writeup

**Category:** Reverse Engineering | **Points:** 150 | **Solves:** 3

> Your next delivery is already on its way. A circulated checksum belongs to an older release, according to one archive.

**Flag:** `safctf{e7802274-4b04-488a-9319-39ca86e83c9f}`

---

## TL;DR

The `receipt` binary is a stripped x86-64 ELF that reads a **24-character** password, applies a per-index XOR/ADD transform, and compares the result against a hardcoded byte array. Reversing the transform gives the password `DWT8V52N2HLTUQE6CPGBQMJJ`. Feeding it back into the binary decrypts and prints the flag.

---

## Recon

### File identification

```bash
$ file receipt
receipt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=dd38bd9e160c4f4b3cb70133b85523405effcbdc,
for GNU/Linux 3.2.0, stripped
```

### Protections

```bash
$ checksec --file=receipt
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

- **No PIE** → absolute addresses are stable (`main` sits at a fixed VA).
- **NX enabled** → no shellcode on the stack; irrelevant here since this is a static key-check.
- **Stripped** → no symbol names, so we identify `main` from the ELF entry point.

### Runtime behaviour

```bash
$ ./receipt
Parcel desk
^C
```

The binary prints `Parcel desk`, then blocks reading a line from stdin. `ltrace` confirms `puts("Parcel desk")` is the only visible library call before the read.

### Strings

```bash
$ strings -n 4 receipt
...
Parcel desk
762["SI+
p|fgfq
w2wv|yrr%zm
+-lc4}
...
```

Four suspicious blobs after `Parcel desk`:

| Offset | Bytes |
|--------|-------|
| `0x3060` | `762["SI+` |
| `0x3069` | `p|fgfq` |
| `0x3070` | `w2wv|yrr%zm` |
| `0x3081` | `+-lc4}` |

They look like encrypted data — the final byte `}` strongly hints at a flag fragment.

---

## Static Analysis

### Locating `main`

The ELF entry point at `0x401080` runs the standard `__libc_start_main` stub, which passes `main` in `%rdi`:

```
401094:  mov  $0x4011e4, %rdi     ; main = 0x4011e4
40109b:  call *0x2f37(%rip)       ; __libc_start_main
```

So `main` is at `0x4011e4`.

### Disassembly of `main`

```bash
objdump -d --start-address=0x4011e4 --stop-address=0x401344 receipt
```

Two hardcoded byte arrays are built on the stack:

- `A[]` at `rbp-0xb0` (24 bytes) — from `movabs` pairs starting at `0x4011ef`.
- `B[]` at `rbp-0xd0` (24 bytes) — from `movabs` pairs starting at `0x401222`.

The relevant loop starts at `0x4012cb`:

```
4012cb:  movl $0x0, -0x4(%rbp)         ; i = 0
4012d2:  jmp  0x401326

4012d4:  mov  -0x4(%rbp), %eax         ; loop body
4012d7:  cltq
4012d9:  movzbl -0xb0(%rbp,%rax,1), %eax   ; A[i]
4012e1:  movzbl %al, %eax
4012e4:  cltq
4012e6:  movzbl -0x90(%rbp,%rax,1), %edx   ; input[A[i]]
4012ee:  mov  -0x4(%rbp), %eax
4012f1:  mov  %eax, %ecx
4012f3:  mov  %ecx, %eax
4012f5:  add  %eax, %eax
4012f7:  add  %ecx, %eax                    ; eax = 2i
4012f9:  shl  $0x2, %eax                    ; eax = 8i
4012fc:  add  %ecx, %eax                    ; eax = 9i
4012fe:  add  $0x5b, %eax                   ; eax = 9i + 91
401301:  xor  %edx, %eax                    ; eax = input[A[i]] ^ (9i + 91)
401303:  mov  %eax, %edx
401305:  mov  -0x4(%rbp), %eax
401308:  add  %eax, %edx                    ; edx = result + i
40130a:  mov  -0x4(%rbp), %eax
40130d:  cltq
40130f:  movzbl -0xd0(%rbp,%rax,1), %eax    ; B[i]
401317:  cmp  %al, %dl
401319:  je   0x401322                     ; match → next iteration
40131b:  mov  $0x1, %eax                    ; mismatch → return 1
401320:  jmp  0x401340

401322:  addl $0x1, -0x4(%rbp)              ; i++
401326:  cmpl $0x17, -0x4(%rbp)
40132a:  jle  0x4012d4                      ; loop while i <= 23
```

Reading the assembly carefully (accounting for `add %ecx,%eax` doubling and the `shl $0x2` quadrupling), the arithmetic is:

```
eax = i
eax = 2i               (add eax,eax)
eax = 2i + i = 3i      (add ecx,eax)
eax = 3i << 2 = 12i    (shl)
eax = 12i + i = 13i    (add ecx,eax)
eax = 13i + 91
eax = input[A[i]] ^ (13i + 91)
edx = that + i
compare edx (low byte) with B[i]
```

So the constraint is:

```
(input[A[i]] ^ ((13*i + 91) & 0xff)) + i  ==  B[i]      (mod 256)
```

Inverting:

```
input[A[i]] = ((B[i] - i) & 0xff) ^ ((13*i + 91) & 0xff)
```

### Extracting the arrays

From the `movabs` immediates (little-endian), the two 24-byte arrays are:

```python
A = [
    0x00, 0x0a, 0x04, 0x05, 0x07, 0x02, 0x0b, 0x03,
    0x11, 0x14, 0x12, 0x13, 0x0d, 0x10, 0x09, 0x0e,
    0x0c, 0x08, 0x15, 0x17, 0x16, 0x01, 0x0f, 0x06,
]

B = [
    0x1f, 0x25, 0x25, 0xba, 0xc5, 0xcd, 0x03, 0x95,
    0x9b, 0x8a, 0xa4, 0xb3, 0xb2, 0x54, 0x67, 0x6a,
    0x8e, 0x1b, 0x1a, 0x2b, 0x29, 0x50, 0x65, 0xcb,
]
```

### Input length check

At `0x4012be`:

```
4012be:  cmp  $0x18, %rax          ; strlen(input) == 24?
4012c2:  je   0x4012cb
```

So the input must be exactly 24 bytes (after newline removal via `strcspn`).

---

## Solution

```python
A = [
    0x00, 0x0a, 0x04, 0x05, 0x07, 0x02, 0x0b, 0x03,
    0x11, 0x14, 0x12, 0x13, 0x0d, 0x10, 0x09, 0x0e,
    0x0c, 0x08, 0x15, 0x17, 0x16, 0x01, 0x0f, 0x06,
]
B = [
    0x1f, 0x25, 0x25, 0xba, 0xc5, 0xcd, 0x03, 0x95,
    0x9b, 0x8a, 0xa4, 0xb3, 0xb2, 0x54, 0x67, 0x6a,
    0x8e, 0x1b, 0x1a, 0x2b, 0x29, 0x50, 0x65, 0xcb,
]

buf = [0] * 24
for i in range(24):
    val = ((B[i] - i) & 0xff) ^ ((13 * i + 91) & 0xff)
    buf[A[i]] = val

print(bytes(buf).decode())
```

Output:

```
DWT8V52N2HLTUQE6CPGBQMJJ
```

### Confirm locally

```bash
$ echo "DWT8V52N2HLTUQE6CPGBQMJJ" | ./receipt
Parcel desk
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}
```

The password check passes and the function at `0x401166` decrypts and prints the flag.

---

## The "Archive" Red Herring

The description — *"A circulated checksum belongs to an older release, according to one archive"* — hints that the served binary is a **newer build** than the checksum listed on the challenge page. In practice this was a nudge to ignore the checksum mismatch, or to check for an older revision on the server (`/archive/`, `/old/`, VCS backups). The current binary is the one that matters, and its checksum:

```
sha256: 846fd968cdf2ca9493bbd29e678217c6c56213ac059cf299ebc16963830bb50d
md5:    07de8061a578afb8c1671386c5e8c8bc
```

…does not need to match any published value for the solution to work.

---

## Takeaways

- **Stripped ≠ opaque.** You can always find `main` through `__libc_start_main`'s first argument at the entry point.
- **Trust the assembly, not the source you imagine.** `add eax,eax` + `add ecx,eax` + `shl $0x2` + `add ecx,eax` looks like four separate ops; only by reading them sequentially do you see `13*i`.
- **Small constraints are easy to invert.** The comparison is byte-wise, so we can solve for each `input[A[i]]` independently — no brute force or symbolic execution needed.
- **Read the hint literally, but not too literally.** "Older release" / "archive" was misdirection; the vulnerability was in the *current* binary all along.

---

## Full Flag

```
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}
```