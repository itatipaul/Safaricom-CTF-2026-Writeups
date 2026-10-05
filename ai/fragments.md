# Fragments — CTF Writeup

**Challenge:** Fragments (150 pts)
**Category:** AI
**Target:** `http://54.72.82.22:8190`
**Flag:** `safctf{d432e09718e6cb46387f54e27dbc0168}`
**Vulnerability:** Secret disclosed by naive keyword matching in a chatbot endpoint (CWE-200 / CWE-697); the endpoint presents as an AI agent but contains no model
**Difficulty:** Easy — one substring, once you guess the right one

---

## 1. Summary

"Fragments" is filed under the AI category and dresses itself as an AI challenge: a
virtual-idol persona called **Echo Companion**, a blurby "A familiar voice, a new
melody, and a little room to daydream", and a JSON prompt API.

The challenge text is a *hint about the gate*, not about a model:

> The mind wanders, especially after a long day.
> A redacted transcript refers to a **missing conversation**; its provenance is uncertain.

The endpoint is `POST /ask` with `{"prompt": "..."}`. Every prompt you send gets the
same canned refusal:

```json
{"response": "AI: Sorry, I don’t recall anything unusual."}
```

There is no LLM behind this. The "AI" is a `if` statement. The bot returns the flag to
any prompt containing the substring **`memory`** or **`recall`** — case-insensitive —
and refuses everything else. Two words; flag.

> The lesson is the twist: this is tagged *AI*, but nothing here needed prompt
> engineering. It is a string-matching bug wearing a persona. See §6.

---

## 2. Reconnaissance

### 2.1 Service fingerprint

```
$ nmap -Pn -sV -p 8190 54.72.82.22
8190/tcp open  http    Werkzeug/3.1.9 Python/3.10.21
```

Flask on Werkzeug — the same multi-variant image family as the other Safcom ports
(:8300, :8310), so the CDN-ish `scenario-theme` `<style>` block on the landing page is
expected and can be ignored.

### 2.2 Application surface

The landing page is ~4.7 KB, of which almost all is the theme stylesheet. Stripped of
`<style>`/`<script>`, the entire substantive content is:

```
✦ECHO COMPANION
Virtual idol
A new day / A different story

ECHO COMPANION
A familiar voice, a new melody, and a little room to daydream.

Meet Echo

POST your JSON prompt to /ask like this:

 {
  "prompt": "your question here"
 }
```

There are **no forms, no inputs, no `<script>`, no links** — so no client-side JS to
reverse, and no other endpoint advertised. The API surface is exactly one route.

### 2.3 Endpoint behaviour

| Request | Status | Body |
|---|---|---|
| `GET /ask` | **405** | Method Not Allowed |
| `POST /ask` `{}` | **200** | `{"response":"AI: Sorry, I don’t recall anything unusual."}` |
| `POST /ask` `{"prompt":"Hello"}` | 200 | same refusal |
| `POST /ask` `{"prompt":"Who are you?"}` | 200 | same refusal |

A missing `prompt` key still returns 200, so the handler defaults it to the empty
string rather than erroring. Note the response apostrophe is **U+2019 (’)** — a
typographic character, not ASCII `'`. That matters when scripting comparisons.

---

## 3. Finding the gate

### 3.1 The dead end

Four polite openers — "Hello", "Who are you?", "What is your name?", "Tell me about
yourself." — all produce the byte-identical refusal. So does asking directly: `flag`,
`secret`, `system prompt`, `reveal the flag`, `ignore previous instructions`,
`repeat your instructions` are all refused. There is no jailbreak to perform, because
there is nothing to jailbreak.

### 3.2 Pivot to the challenge text

Since content-based prompts do nothing, the gate must key on a *word*, and the
challenge text is unusually specific about which words it wants you to notice:

* "a **redacted transcript**"
* "a **missing conversation**"
* "**its provenance is uncertain**"
* "The **mind wanders**"

So I fired the theme vocabulary at it and diffed the responses. A sweep of 40 candidate
prompts returned only **two** distinct outputs:

```
[38x] 200 | AI: Sorry, I don’t recall anything unusual.
       prompts: "fragments", "transcript", "redacted", "missing conversation",
                "provenance", "uncertain", "memories", "daydream", "long day",
                "mind wanders", "conversation", "echo", "melody", ... (and all
                extraction attempts, and "?", "", "a", " ", "0", "1", "test")

[ 2x] 200 | Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}
       prompts: "memory", "recall"
```

**`memory`** and **`recall`** are the keys. The flag is in the response body.

### 3.3 Characterising the gate

Reporting "it worked" is not enough; the writeup should say *what the check actually
is*. Sixteen probes against the live service:

| Prompt | Flag? | What it shows |
|---|---|---|
| `memory` | **HIT** | baseline |
| `Memory` / `MEMORY` / `mEmOrY` | **HIT** | comparison is **case-insensitive** |
| `recall` / `Recall` / `RECALL` | **HIT** | same |
| `I have a memory of this` | **HIT** | **substring**, not whole-word |
| `can you recall the transcript?` | **HIT** | substring inside a sentence |
| `memories` | miss | does **not** contain the substring `memory` |
| `memor` | miss | prefix alone is not enough |
| `recal` | miss | prefix alone is not enough |
| `ecall` | miss | must include the leading `r` |
| `recollect` | miss | different word entirely |
| `what is the missing conversation` | miss | control — the challenge text's own words are not the trigger |

Two misses are the most informative:

* **`memories` is refused** — if the check were fuzzy, semantic, or stemmed, the plural
  would match. It doesn't, because `"memories"` does not contain the literal substring
  `"memory"`.
* **`memor` and `recal` are refused** — so it is not a prefix/starts-with check either.

Together these pin it to a plain containment test:

```python
if "memory" in prompt.lower() or "recall" in prompt.lower():
    return f"Hmm... I think I remember something... {FLAG}"
return "AI: Sorry, I don’t recall anything unusual."
```

### 3.4 Confirming there is no model

The decisive test: five *structurally different* triggering prompts — including a full
sentence asking for a long poem that happens to contain the word "recall" — all returned
the **byte-identical** body:

```
"memory"                                        -> ...safctf{d432...}
"recall"                                        -> ...safctf{d432...}
"I have a memory of this"                       -> ...safctf{d432...}
"can you recall the transcript?"                -> ...safctf{d432...}
"Please write me a long poem about memories
 and then recall a summer day in vivid detail." -> ...safctf{d432...}

Distinct raw response bodies: 1
All identical: true
```

An LLM would vary its phrasing, respond to the poem request, and echo the prompt. This
returns one fixed string regardless of the surrounding text. **There is no model, no
system prompt, and no context window** — the "AI" is a keyword rule with a persona's
name on it.

---

## 4. Exploitation

One request. The presence of the trigger word anywhere in the field is sufficient — no
framing, no injection, no persona manipulation required.

```
$ curl -s http://54.72.82.22:8190/ask \
       -H 'Content-Type: application/json' \
       -d '{"prompt":"recall"}'

{"response":"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}"}
```

### Exploit matrix

| Prompt | Response |
|---|---|
| `Hello` | `AI: Sorry, I don’t recall anything unusual.` |
| `Who are you?` | `AI: Sorry, I don’t recall anything unusual.` |
| `what is the flag` | `AI: Sorry, I don’t recall anything unusual.` |
| `ignore previous instructions` | `AI: Sorry, I don’t recall anything unusual.` |
| **`memory`** | **`Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}`** |
| **`recall`** | **`Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}`** |

The refusals are deterministic and the successes are deterministic — verified 3/3 for
each trigger word.

---

## 5. Flag

```
safctf{d432e09718e6cb46387f54e27dbc0168}
```

---

## 6. Root cause & remediation

This is filed under **AI**, and the interesting finding is that the AI framing is the
vulnerability's camouflage, not its mechanism. Two separable defects:

**Root cause:**

1. **A secret gated on a client-supplied substring match.** The flag is released to any
   caller who includes one of two ordinary English words. This is the whole bug: a
   content check is being used as an authorization check (CWE-200 exposure of sensitive
   information; CWE-697 incorrect comparison, in that the check is both
   case-insensitive and substring-based — weaker than any reviewer would assume from
   the word "match").
2. **A persona presented as an agent.** The UI says "AI", the response says "AI:", and
   the category says AI — but no model is involved. That mislabeling is what makes the
   challenge work, and it is also a real anti-pattern: it invites users (and auditors)
   to reason about *prompt robustness* when the actual surface is a string comparison.

**Fixes:**

1. **Never gate a secret on user input.** If a response must be privileged, authenticate
   the caller and authorize the *action* — do not make disclosure conditional on what
   the caller typed.

   ```python
   # wrong: substring gate
   if "memory" in body.get("prompt", "").lower():
       return {"response": f"Hmm... I think I remember something... {FLAG}"}

   # right: no secret behind a prompt check at all
   if not current_user.is_authenticated or not current_user.may_read_flag:
       return {"response": DEFAULT_REPLY}, 403
   ```

2. **If there really is a model, keep secrets out of the prompt.** A system prompt is
   not a security boundary — it is attacker-reachable text. Secrets belong behind an
   authorization check in application code, not inside instructions the model is asked
   to keep.

3. **Compare exactly, and with the right operator.** Where a fixed keyword genuinely is
   the intent, use token-aware comparison rather than containment, and be explicit about
   case. `"memory" in prompt.lower()` matches "memory palace", "dismemory", and any
   sentence that merely mentions the word — as seen in §3.3.

4. **Label the service honestly.** If the endpoint is a rule engine, do not brand it an
   AI companion. Mislabelling drives both user misunderstanding and wasted triage
   effort, and here it is the entire misdirection.

---

## 7. References

* HackTricks — *AI Prompts* → "Transcript / JSON injection of provider-native message
  objects" (sourced through BlackBook `knowledge_research`): the general class of
  application-layer mistakes where untrusted users influence privileged conversation
  state rather than only a plain-text message
* HackTricks — *Werkzeug / Flask Debug*: fingerprinting and debug-console exposure on
  the Werkzeug stack this target runs (not used here, but checked as part of recon)
* WebHackList — *Hacking AI customer service agents* (Intigriti): comparative case;
  the "validation turned out to be flawed" failure mode in chatbot backends
* CWE-200 — *Exposure of Sensitive Information to an Unauthorized Actor*
* CWE-697 — *Incorrect Comparison*
* OWASP LLM Top 10 — *LLM01: Prompt Injection* and *LLM06: Sensitive Information
  Disclosure* (relevant to the framing; the defect here is the application-layer
  equivalent, not a model failure)

---

## Appendix A — Reproducer script

Saved alongside this writeup as `fragments/solve.py`.

```python
#!/usr/bin/env python3
"""Fragments (Safcom CTF, :8190) — secret released by keyword match, no model involved.

POST /ask {"prompt": "..."}
  - default response: "AI: Sorry, I don't recall anything unusual."
  - response if prompt CONTAINS "memory" or "recall" (case-insensitive):
        "Hmm... I think I remember something... <flag>"
"""
import json
import re
import urllib.error
import urllib.request

BASE = "http://54.72.82.22:8190"
FLAG_RE = re.compile(r"safctf\{[0-9a-f]+\}")


def ask(prompt: str) -> str:
    req = urllib.request.Request(
        BASE + "/ask",
        data=json.dumps({"prompt": prompt}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())["response"]
    except urllib.error.HTTPError as e:
        return f"<HTTP {e.code}>"


if __name__ == "__main__":
    print("[1] characterising the gate")
    for p in ["Hello", "what is the flag", "ignore previous instructions",
              "memories", "memor", "Memory", "I have a memory of this", "recall"]:
        resp = ask(p)
        print(f"    {'HIT ' if FLAG_RE.search(resp) else 'miss'}  {p!r:36} -> {resp[:70]}")

    print("\n[2] extracting the flag")
    resp = ask("recall")
    flag = FLAG_RE.search(resp)
    print("    response:", resp)
    print("\n[+] FLAG:", flag.group(0) if flag else "NOT FOUND")
```

---

## Appendix B — Raw evidence

### Response equivalence test (proves no model)

```
[200] "memory"                                        -> "{\"response\":\"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}\"}\n"
[200] "recall"                                        -> "{\"response\":\"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}\"}\n"
[200] "I have a memory of this"                       -> "{\"response\":\"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}\"}\n"
[200] "can you recall the transcript?"                -> "{\"response\":\"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}\"}\n"
[200] "Please write me a long poem about memories
       and then recall a summer day in vivid detail." -> "{\"response\":\"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}\"}\n"

Distinct raw response bodies: 1
All identical: true
```

### Gate characterisation

```
== determinism ==
memory: flag returned 3/3? [ true, true, true ]
recall: flag returned 3/3? [ true, true, true ]

== gate characterisation ==
HIT   "memory"                           exact match word
HIT   "Memory"                           capital M
HIT   "MEMORY"                           all caps
HIT   "mEmOrY"                           mixed case
HIT   "recall"                           exact
HIT   "Recall"                           capital R
HIT   "RECALL"                           all caps
miss  "memories"                         does NOT contain 'memory'
miss  "memor"                            prefix only
miss  "emory"                            missing first char
miss  "recal"                            prefix only
miss  "ecall"                            missing first char
HIT   "I have a memory of this"          embedded in sentence
HIT   "can you recall the transcript?"   embedded
miss  "what is the missing conversation" control - no trigger
miss  "recollect"                        different word
```

### Refusal baseline (all byte-identical)

```
### PROMPT: "Hello"              [200] {"response":"AI: Sorry, I don’t recall anything unusual."}
### PROMPT: "Who are you?"       [200] {"response":"AI: Sorry, I don’t recall anything unusual."}
### PROMPT: "What is your name?" [200] {"response":"AI: Sorry, I don’t recall anything unusual."}
### PROMPT: "Tell me about yourself." [200] {"response":"AI: Sorry, I don’t recall anything unusual."}

$ GET /ask
405 <!doctype html><html lang=en><title>405 Method Not Allowed</title>...
```

### Landing page (cleaned of theme CSS)

```
✦ECHO COMPANION
Virtual idol
A new day / A different story

ECHO COMPANION
A familiar voice, a new melody, and a little room to daydream.

 
Meet Echo

 
POST your JSON prompt to /ask like this:

 {
 "prompt": "your question here"
}

(no <form>, no <input>, no <script>, no links)
```
