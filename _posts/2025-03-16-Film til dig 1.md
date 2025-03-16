---
title: Film til dig Pt. 1 🍿
date: 2025-03-16 12:52 +/-TTTT
categories: [CTF Writeups, DDC25]
tags: [DDC, Boot2Root, Web Exploitation]     # TAG names should always be lowercase
media_subpath: /assets/img/FilmTilDig
---

## 🗒️ Challenge description 
> 0xlime synes du skal sætte dig ned og se nogle film, der er 2 flag, find film til dig på {endpoint}, husk at dele hvad du synes g

This is a Web Exploitation challenge on a movie review website.
## 📂 Directory structure
The codebase for this challenge is rather large, here is an overview.
```filestructure
FILM TIL DIG
├── src/
│   ├── static/
│   │   └── tailwind.css
│   └── templates/
│       ├── admin.html
│       ├── auth_base.html
│       ├── impersonate.html
│       ├── index.html
│       ├── login.html
│       ├── movie.html
│       ├── movies.html
│       ├── profile.html
│       ├── register.html
│       └── review.html
├── app.py
├── bot.py
├── db.py
├── utils.py
├── requirements.txt
├── default.vcl
├── docker-compose.yml
├── Dockerfile
└── supervisord.conf
```
The website backend is using Python with the Flask library. Frontend uses Tailwind CSS.

## 🕵️‍♂️ Initial analysis 
- The website is run in a docker container. 
- The docker container uses a Varnish cache server.
- The website has a login page, a register page, a movie review page, and an admin page.
- The website has user roles: `user`, `moderator`, and `admin`.

Let's take a look at the website.

## 🌐 The website
Upon visiting the website, we are greeted with a login/register page.
Since we have access to the source code, and therefore also the database, we could try looking for credentials there.
The db.py script has the following lines:
```python
c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'd0ffe22ae348aeb5660fc214ffcdf5850c4da997', 'admin')")
c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('moderator@movie-review.local', '242f14909efe65354bed83839bccb71161f202fb', 'moderator')")
c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('____FIRSTFLAG____', '', 'user')")
```
{: .nolineno }
{: file="src/db.py" }

Two things become apparent here:
- The passwords are hashed.
- The first flag is the username of a user.

Considering that the passwords are hashed, we can't directly use them to login, as the hashes are calculated server-side.
A valid approach could be to attempt to crack the hashes. 
This does, however, not seem to yield any results. (Using the well known rockyou.txt wordlist)
So we need to find another way to login. Luckily, the website has a register page, so we could just make a new user.

## ✍ Registering a new user
When we attempt to register a new user, the form contains a "secret code" field.
Looking in our source code again, a `verify_secret_code` function is defined in the `utils.py` script.
The secret code is not just one hardcoded value, but a list of checks that the code must pass.
The code must be split into 3 parts, separated by a `-`.

- The first check ensures the product of the ASCII values of the first four characters plus 1 is a large prime number (≥133333337).
- The second check verifies that XORing all ASCII values of the middle four characters equals exactly 0x41 (ASCII 'A').
- The third check confirms that the product of the ASCII values of the final three characters is divisible by 20000.

We can write some Python code that bruteforces each segment in the secret code:
```python
def brute1():
    for i in range(165):
        for j in range(165):
            for k in range(165):
                product = (i*j*k*ord("-"))+1
                if product > 133333337 and is_prime(product):
                    print(chr(i), chr(j), chr(k))
                    return
def brute2():
    for i in range(50, 165):
        for j in range(50, 165):
            for k in range(50, 165):
                for l in range(50, 165):
                    result = i^j^k^l
                    if result ^ 0x41 == 0:
                        print(i,j,k,l)
                        print(chr(i), chr(j), chr(k), chr(l))
                        return
def brute3():
    for i in range(50, 165):
        for j in range(50, 165):
            for k in range(50, 165):
                product = i*j*k
                if product % 20000 == 0:
                    print(i,j,k)
                    print(chr(i), chr(j), chr(k))
                    return
```
{: .nolineno }
{: file="bruteforce.py" }

Running these functions and combining the results, we get the secret code: `o¤¤--222s-228`

It uses some unusual characters, but it works, and we can sign up a new user.
We are now past the boring part of the challenge, and can start looking deeper.

## 🐛 Update logic flaw
After logging in, we are presented with a grid of movies. Clicking each movie takes us to a review page, where we can write a review.
At first glance, this seems like an obvious XSS vulnerability. But looking in the source code, we can see that everything is properly escaped.

We also have a profile page, where we can change our username and password.
Another potential vulnerability could be SQL injections, but again looking in the source code, we can see that the queries are properly parameterized.

However, while looking in the source code I spotted something interesting in the `update_user` function.
```python
if new_username is not None:
    if not validate_email(new_username):
        return jsonify({'error': 'Invalid email address'}), 400
    
    conn = sqlite3.connect('movies.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (new_username,))
    user = c.fetchone()
    conn.close()

    if user and user[1] != session['username']:
        return jsonify({'error': 'Username already taken'}), 400

    conn = sqlite3.connect('movies.db')
    c = conn.cursor()
    c.execute("UPDATE users SET username = ? WHERE username = ?", (new_username.strip(), session['username']))
    conn.commit()
    conn.close()

    session['username'] = new_username.strip()

if new_password is not None:
    hashed_password = hashlib.sha1(new_password.encode()).hexdigest()
    conn = sqlite3.connect('movies.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, session['username']))
    conn.commit()
    conn.close()
```
{: .nolineno }
{: file="src/app.py" }

Can you spot the vulnerability? It's not obvious at first glance, but the vulnerability is in the `new_username.strip()` function.
This function removes all leading and trailing whitespaces from the username. Which is pretty normal for user input.
However, the username is being stripped AFTER the check for collisions. 

This means that we may be able to set a username that doesn't at first collide with an existing username, but after stripping, it does.
Also, the username has to be an email address. Looking in the source code database, we can see that the admin username is `admin`, which wouldn't pass the email check. But the moderator username is `moderator@movie-review.local`, which would pass the email check.
We still need to find something to append to the email, so that it doesn't at first collide in the SQL query, but after stripping it does.

We can again use the bruteforce method to craft a malicious email.
```python
def validate_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def brute4():
    for i in range(100000):
        email = "moderator@movie-review.local" + chr(i)

        if not validate_email(email):
            continue

        if email == email.strip():
            continue

        print(i)
        print(chr(i))
```
{: .nolineno }
{: file="bruteforce.py" }

Running this function, we get the character code 10, which is a newline character.
Now attempting to update our user with a new password and the email: `moderator@movie-review.local\n` (Notice the newline character at the end), we get a success message. We successfully avoided the first collision check, stripped out the newline character, and ended up setting the password for the moderator user. (We had to craft the request manually, as the website doesn't allow for newlines in the input fields. I used Burp Suite for this)

And we are now able to login as moderator!

## 📝 Review Moderation

Great, now what? Looking around the website, the moderator still seemingly can not see anything the user can not.
The only difference is that we can "report" reviews. Looking at the source code, this makes a headless browser bot visit the review, and do nothing more. The bot is logged in with admin credentials. Again, this looks like an [XSS](https://portswigger.net/web-security/cross-site-scripting){:target="_blank"} or [CSRF](https://www.cloudflare.com/learning/security/threats/cross-site-request-forgery/){:target="_blank"} vulnerability. But since the review content is properly escaped, we can not do an XSS attack to exfiltrate the admin cookies. We can, however, quite easily modify the report review request to any url on the same domain.

In the source code we can see that there is an admin panel. And even an API endpoint for fetching all users. This would be great, except for the fact that the admin bot never returns any data at all, it only visits the provided URL. It also makes sure to only visit URLs on the same domain, which I wasn't able to bypass. And also only with GET requests, so we can not make it change with the website in any way.

At this point I was rather stuck. Until I remembered the Varnish cache server. The configuration file hides itself outside the Flask app, and is located in the root directory of the Docker container. Looking in the cache configuration file, we see that it cache every URL containing `js|css|png|gif`.

```vcl
sub vcl_hash {
    hash_data(req.url);
    if (req.url ~ "\.(js|css|png|gif)$") { # Tailwind.css is very heavy so we want to cache it. 
        return (lookup);
    }
}

sub vcl_recv {
    if (req.url ~ "\.(js|css|png|gif)$") {
        set req.http.Cache-Control = "max-age=10";
        return (hash);
    }
}
```
{: .nolineno }
{: file="default.vcl" }

This seems promising for a [cache poisoning vulnerability](https://portswigger.net/web-security/web-cache-poisoning){:target="_blank"}!

But the cache server only caches files with the extensions `js|css|png|gif`. 😞

Actually not quite. It will cache **any** url containing those extensions. If we can append a malicious extension to the API endpoint, while still making it look like a valid URL, we can cache the response. 

We could potentially add this to the API endpoint `/api/admin/get_users` like this `/api/admin/get_users?q=.css`. While this may give us the flag, we can take it a step further. There is another endpoint that returns data for any user, including a session token. This endpoint is `/api/user/<path:text>`. If we visit this URL on our own, we get our currently logged in session ID. If we visit the URL with the admin bot, we get the session ID for the admin.

So, adding a malicious extension to this endpoint, we can cache the response from the admin bot, and get the admin session ID.
I used this as a payload for the bot: `/api/user/admin/.css` and quickly visited the URL with my own browser. And there it was, the admin session ID.

Setting the session cookie in my own browser, I am now logged in as admin. And the flag is right there in the admin panel, containing a list of the users.

🚩`DDC{b4d_s1gnup_b4d_r3g3x???_0xlimE_g0n3_b3_s4444d...}`🚩

{: .prompt-info } 
> Continue to [Film til dig Pt. 2]({% post_url 2025-03-16-Film til dig 2%})

## 🤓 TL;DR
1. Bruteforced the secret code for the registration page:
    - Crafted a valid secure sign-up code `o¤¤--222s-228`
    - Registered a new user with the secret code
2. Exploited a logic flaw in the update username function:
    - Found that username collision check happens before stripping whitespace
    - Used `moderator@movie-review.local\n` to take over the moderator account
3. Leveraged web cache poisoning vulnerability with admin bot:
    - Varnish cache would cache any URL containing `.js|.css|.png|.gif`
    - Used the admin bot and `/api/user/admin/.css` to poison cache with admin's session token
    - Hit the cache and aquired the admin session token
    - Accessed the admin panel, optaining the flag 🚩