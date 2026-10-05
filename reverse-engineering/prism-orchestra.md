# Prism Orchestra — Writeup

**Category:** Reverse Engineering | **Points:** 450 | **Solves:** 3

> Every instrument has its place, and every note contributes to the whole. Under the stage lights, the colours shift as the orchestra plays its familiar arrangement.
> Everything sounds perfectly in tune.

**Flag:** `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}`

---

## TL;DR

The `receipt` binary is a stripped x86-64 ELF that reads a 24-byte password, opens `/app/downloads/score.bin`, and applies a **3-byte bytecode program** (XOR / ADD / ROL / SWAP) to the input buffer. The result is compared to a hardcoded 24-byte target. Inverting the bytecode in reverse order recovers the password `DDPU5WDMVRKQ2APHL7WPM78W`, which decrypts and prints the flag.

---

## Recon

### File identification

```bash
$ file receipt
receipt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=abad5ee13cd19d955d81b7f53b36c70471506c6b,
for GNU/Linux 3.2.0, stripped

$ file score.bin
score.bin: data