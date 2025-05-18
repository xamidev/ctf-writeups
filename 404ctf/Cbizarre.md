# Cbizarre

We're provided with a binary file. Checking the usual stuff:

```
$ file chall2 
chall2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=683fe4c494b6b7dc5df519f9299a42f6616677ff, for GNU/Linux 3.2.0, not stripped
```

```
$ checksec --file=chall2           
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   43 Symbols        No    0               2               chall2
```

Some protections are enabled as we can see (NX, PIE). We can proceed to decompile the binary using Ghidra, and after some stripping of the useless/usual lines, and after renaming some labels, we find the interesting part of the code:

```c
  if (argc == 2) {
    length = strlen((char *)argv[1]);
    if (length == 0x14) {
      if (*(char *)(argv[1] + 5) != 'Z') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0xc) != 'o') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)argv[1] != 'f') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0x12) != '1') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 7) != '%') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 3) != 'M') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 9) != 'y') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0x10) != 'v') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0xe) != 'n') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 1) != 'a') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0x13) != 'x') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 6) != 'a') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0xf) != 'M') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 8) != '3') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 4) != 'P') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0xb) != 'K') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 10) != 'N') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0x11) != '%') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 2) != 'V') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      if (*(char *)(argv[1] + 0xd) != '@') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
      local_28 = 0x661a1c040e625152;
      local_20 = 0x492f7e4954;
      uStack_1b = 0x200233;
      uStack_18 = 0x5026906;
      local_10 = xor(&local_28,argv[1],0x14);
      printf("Bravo ! Vous avez le flag ! %s\n",local_10);
      result = 0;
    }
    else {
      fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
      result = 1;
    }
  }
  else {
    fprintf(stderr,"Usage: %s <password>\n",*argv);
    result = 1;
  }
  return result;
}
```

As we can see here, we need to provide a password as a command-line argument to the binary. The first information we gather about that password is that its length is 0x14 bytes (which is 20 in decimal).
Then, we see that the program compares some position in memory, with an offset relative to the start of the password string, against a byte: in the below example, the program compares the byte offseted by 5 against 'Z':
```c
if (*(char *)(argv[1] + 5) != 'Z') {
        fwrite("Error: Incorrect password.\n",1,0x1b,stderr);
        exit(1);
      }
```
That code part can simply be resumed with this pseudocode:
```
if (password+5 != 'Z') then exit
```
Looking at all those small conditional statements, it looks like the password can be retrieved by looking at each comparison and assembling all the letters that are compared, in the right order.

After getting through all of the checks manually and writing down the byte at the correct offset, we're left with this string: `faVMPZa%3yNKo@nMv%1x`.

Throwing it as input to the program gives us the flag:

```
$ ./chall2 faVMPZa%3yNKo@nMv%1x
Bravo ! Vous avez le flag ! 404CTF{Cg00d&slmpL3}
```
