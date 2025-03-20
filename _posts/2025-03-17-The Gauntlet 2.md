---
title: The Gauntlet Pt. 2 🥈
date: 2025-03-17 00:51 +/-TTTT
categories: [CTF Writeups, DDC25]
tags: [DDC, Boot2Root, Web Exploitation] 
media_subpath: /assets/img/TheGauntlet
---

{: .prompt-info } 
> This challenge is a continuation of the previous challenge [The Gauntlet Pt. 1]({% post_url 2025-03-17-The Gauntlet 1%})

{: .prompt-warning } 
> This writeup is WIP and may be incomplete.


## 🗒️ Challenge description
>So, part two.. gitgud, get root..

## 😎 Writeup

Running `whoami` reveals that we are `user1`. Looking in our home directory, we see a file named `testBin`, which is owned by `user2` and has the SUID bit set. This means that we can run the binary as `user2` and potentially escalate our privileges.

Running the `testBin` binary gives us an output that looks like the `xdd` utility in Linux. XDD is normaly used to view the contents of a file in hexadecimal format. We may be able to read user2 files using this binary, or maybe even escalate our privileges to user2.

But something isn't quite right with `testBin`. Checking the size of the binary reveals that it is a different size than the original `xdd` binary. This could mean that the binary is a wrapper around the original `xdd` binary, and not just a copy. Let's export the binary to our local machine and analyze it with Ghidra. Also, the binary for some reason want's us to always use one parameter with it.

Decompiling the `testBin` binary in Ghidra reveals that the binary is indeed a wrapper around the original `xdd` binary. The binary simply calls `system("xdd")` and then exits. This is however an unsafe way to call `xdd`, as it is vulnerable to path injection.

We can exploit this vulnerability by creating a malicious `xdd` shell script that executes a shell for us. We just have to make sure our malicious `xdd` script is in the path before the original `xdd` binary.

```bash
$ echo '#!/bin/sh -p\n/bin/sh -p' > xdd
$ chmod +x xdd
$ export PATH=.:$PATH
$ ./testBin -h
```

Remeber to pass a parameter to testBin, or it will exit before exectuing the system call.

Now if we run `whoami` we'll see that we are `user2`. Looking in the `/home/user2` directory, we find one file `runMe.sh`.
This script just echoes "If only I could be something usefull...". The script is owned by root, but doesn't have the SUID bit set. We can't directly write to it as user2, but we can delete and replace it.

I must admit, I was stuck at this point for a loooooong time. Running `sudo -l` should reveal info about what we can run as sudo. But it just prompts for user1 password instead. Which is odd. Running `id` reveals that we still have our original UID as user1, but EUID is user2. At this point I was confused and wanted a better shell. Running `ps aux` i noticed that `sshd` was running. 

We can create the `.ssh` directory in `/home/user2` and add our public key to the `authorized_keys` file. This will allow us to SSH into the box as user2. 

```bash
$ mkdir /home/user2/.ssh
$ ssh-keygen
$ cat ~/.ssh/id_rsa.pub > /home/user2/.ssh/authorized_keys
$ cat /home/user2/.ssh/id_rsa
```

Now we can successfully connect to user2 with SSH. Which gives us a much nicer shell. Now running `sudo -l` reveals that we can run `/usr/bin/runMe.sh` as `user3` without a password. We can delete the original write-protected `runMe.sh` and replace it with a malicious script that gives us a shell as `user3`.

```bash
$ rm -f /home/user2/runMe.sh
$ echo '/bin/sh' > runMe.sh
$ chmod +x runMe.sh
$ sudo /usr/bin/runMe.sh
```

Now we are `user3`. But the user3 home directory is empty! 🤯

Running `sudo -l` reveals that we can run `/usr/sbin/useradd` as `root` without a password. We can use this to create a new user with root privileges.

```bash
$ sudo -u root useradd -o -u 0 -m -k /home/user2 user4
```

- `-o` allows us to create a user with the same UID as an existing user.
- `-u 0` sets the UID to 0, which is the root user.
- `-m` creates a home directory for the user.
- `-k /home/user2` copies the contents of the `/home/user2` directory to the new user's home directory. This is useful because the `/home/user2` directory contains our SSH keys, which can then be used to SSH into the new user aswell.

Now we can SSH into the box as `user4` and read the flag in `/root/root.flag`.

```bash
$ whoami
  user4
$ ./root/root.flag
  Press enter within 3 seconds: 
  Secret flag: DDC{1_h0p3_y0u_enj0y3d_my_f1r27_B2R}
```

Flag aquired! 🚩


## 🤓 TL;DR
1. Found SUID binary `testBin` that wraps the `xdd` binary.
2. Exploited path injection vulnerability in SUID binary `testBin` to get a shell as `user2`.
3. Found `runMe.sh` script in `/home/user2` that can be run as `user3` without a password.
4. Replaced `runMe.sh` with a malicious script to get a shell as `user3`.
5. Found that `useradd` can be run as `root` without a password.
6. Created a new user `user4` with UID 0 and copied the contents of `/home/user2` to the new user's home directory.
7. SSHed into the box as `user4` and read the flag in `/root/root.flag`.
