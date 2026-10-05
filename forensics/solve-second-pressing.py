#!/usr/bin/env python3
"""
Second Pressing (Safcom CTF, forensics, 250 pts) -- solve script
Target: http://54.72.82.22:8460

Chain:
  1. GET /downloads/listening-room.zip -> library.db, library.db-wal,
     library.db-shm, desk.log
  2. The db alone is EMPTY (0 rows): the live data sits in the uncheckpointed WAL.
     A naive sqlite3 open shows one row: (1,'Test pressing','withdrawn') -- the
     revised ("second pressing") catalogue entry.
  3. Parse library.db-wal by hand. Two frames, both page 2, both COMMIT:
       frame0 @32    -> the ORIGINAL row ("first pressing")
       frame1 @4152  -> the revision
     Frame 0's receipt is a zlib+base64 blob ("eJw..." / 0x78 0x9c).
  4. base64-decode + zlib-inflate that blob ->
       safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
     THAT DECODED VALUE IS THE FLAG.

  NOTE: /submit is a DECOY on this port. It accepts the receipt (any well-formed
  wrong answer is 403, so it validates by value) but answers with a DIFFERENT,
  flag-shaped string -- safctf{34a793a0d11032abb97236fafc9b30c4} -- which the
  scoring platform REJECTS. We still call it below, labelled as a decoy, because
  the contrast is the point of the challenge.

CRITICAL: read the raw WAL bytes BEFORE any sqlite3.connect(). Opening the DB
normally checkpoints the WAL and DELETES library.db-wal -- the evidence is gone.

Run: python3 solve.py
"""
import base64
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import urllib.request
import zipfile
import zlib

BASE = "http://54.72.82.22:8460"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def wal_frames(wal: bytes):
    """Return (pagesize, [(offset, page_number, db_size_after_commit), ...]).

    WAL layout: 32-byte header, then frames of
        24-byte frame header + pagesize byte page image.
    Frame header: pgno u32 | dbsize u32 | salt u32 x2 | checksum u32 x2
    A nonzero dbsize marks the frame as a COMMIT.
    """
    pagesize = int.from_bytes(wal[8:12], "big")
    offset = 32
    out = []
    while offset + 24 + pagesize <= len(wal):
        pgno = int.from_bytes(wal[offset:offset + 4], "big")
        dbsize = int.from_bytes(wal[offset + 4:offset + 8], "big")
        out.append((offset, pgno, dbsize))
        offset += 24 + pagesize
    return pagesize, out


def main():
    blob = fetch(f"{BASE}/downloads/listening-room.zip")
    print(f"[*] listening-room.zip: {len(blob)} bytes")
    z = zipfile.ZipFile(io.BytesIO(blob))
    print(f"[*] members: {z.namelist()}")
    print("[*] desk.log:\n" + z.read("desk.log").decode().rstrip())

    work = tempfile.mkdtemp()
    for name in z.namelist():
        with open(os.path.join(work, name), "wb") as fh:
            fh.write(z.read(name))

    # -- 1. RAW WAL FIRST, before sqlite3 can checkpoint it away ---------------
    wal = open(os.path.join(work, "library.db-wal"), "rb").read()
    pagesize, frames = wal_frames(wal)
    print(f"[*] WAL: {len(wal)} B  pagesize={pagesize}  "
          f"salt={wal[16:24].hex()}")
    for i, (off, pgno, dbsize) in enumerate(frames):
        print(f"[*] frame{i}: offset={off} page={pgno} dbsize={dbsize} "
              f"({'COMMIT' if dbsize else 'no-commit'})")

    # -- 2. recover the overwritten receipt from the earliest frame ------------
    # Receipts are zlib+base64, i.e. b64 text beginning "eJ"; the original is
    # the longest such blob present (the revision stores the literal 'withdrawn',
    # which leaves a shorter stale copy of the receipt in its page).
    candidates = sorted(set(re.findall(rb"eJ[A-Za-z0-9+/=]{20,}", wal)), key=len)
    if len(candidates) > 1:
        print(f"[*] {len(candidates)} blobs found; longest is the complete one")
    receipt = candidates[-1].decode()
    print(f"[+] frame0 receipt blob : {receipt}")
    raw = base64.b64decode(receipt)
    print(f"[+] decoded bytes       : {raw[:4].hex()}  (zlib stream)")
    token = zlib.decompress(raw).decode()
    print(f"[+] RECOVERED RECEIPT   : {token}")

    # -- 3. show what the naive approach yields (the revision) -----------------
    db_only = os.path.join(tempfile.mkdtemp(), "library.db")
    shutil.copy(os.path.join(work, "library.db"), db_only)
    con = sqlite3.connect(db_only)
    print(f"[*] db without WAL      : "
          f"{con.execute('select count(*) from pressings').fetchone()[0]} rows")
    con.close()

    con = sqlite3.connect(os.path.join(work, "library.db"))  # checkpoints the WAL
    print(f"[*] db with WAL applied : "
          f"{con.execute('select id,title,receipt from pressings').fetchall()}")
    con.close()
    print(f"[*] WAL after that open : "
          f"exists={os.path.exists(os.path.join(work, 'library.db-wal'))}")

    # -- 4. the /submit decoy --------------------------------------------------
    # The service accepts the receipt by value but hands back a fake flag.
    body = json.dumps({"answer": token}).encode()
    req = urllib.request.Request(
        f"{BASE}/submit", data=body, headers={"Content-Type": "application/json"}
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
    decoy = resp.get("message")
    print(f"[!] /submit decoy reply : {decoy}  (ok={resp.get('ok')})")
    print("[!] ^ NOT the flag -- this endpoint returns a flag-shaped fake.")

    shutil.rmtree(work, ignore_errors=True)

    print(f"\nFLAG = {token}")


if __name__ == "__main__":
    main()
