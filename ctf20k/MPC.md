# MPC (Magic Password Checker)

The challenge starts with a binary file, that has the following behavior:

```
$ ./password_checker 
Enter a password: test
Password is invalid.
```

We will have to guess the password here. There is no source code available for that program, therefore we have to disassemble it using a tool like Ghidra. The decompiled main function looks like this:

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined1 local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter a password: ");
  __isoc99_scanf(&DAT_004b603b,local_78);
  iVar1 = is_valid_password(local_78);
  if (iVar1 == 0) {
    puts("Password is invalid.");
  }
  else {
    puts("Password is valid.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The program asks for user input, passes it through the `is_valid_password` function and outputs text accordingly. Let's analyze this function:

```c
undefined8 is_valid_password(char *param_1)

{
  char cVar1;
  size_t sVar2;
  undefined8 uVar3;
  int local_10;
  
  sVar2 = strlen(param_1);
  if ((int)sVar2 == 0x17) {
    for (local_10 = 0; local_10 < 0x17; local_10 = local_10 + 1) {
      cVar1 = transform_char((int)param_1[local_10],local_10);
      if (cVar1 != valid_password_encrypted[local_10]) {
        return 0;
      }
    }
    cVar1 = transform_char((int)param_1[2],2);
    if (cVar1 == '\x1f') {
      cVar1 = transform_char((int)param_1[5],5);
      if (cVar1 == '\x1f') {
        cVar1 = transform_char((int)param_1[8],8);
        if (cVar1 == '\v') {
          uVar3 = 1;
        }
        else {
          uVar3 = 0;
        }
      }
      else {
        uVar3 = 0;
      }
    }
    else {
      uVar3 = 0;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}
```

The function loops through all characters in the given string (user input), and passes each of them into the `transform_char` function. It then checks each char against the `valid_password_encrypted` string at the same index. That means, if we get the encrypted version of the password, and we pass it through an inverse version of `transform_char`, we could get the right password..

Decompiling `transform_char` gives us this:

```c
uint transform_char(byte param_1,int param_2)

{
  return param_2 + (param_1 ^ 0x33) ^ 0x55;
}
```

The function is pretty straightforward, as it consists of simple bitwise XOR operations, and one addition. Keeping in mind that both addition and bitwise-XOR have the same priority in computation, and considering the classical left-to-right calculation order, and knowing that XORing two times against the same number gives back the original value, inversing it gives:

```c
param_1 ^ 0x55 - param_2 ^ 0x33
```

Now we have to find the encrypted password. Using the `nm` tool, we can find the memory address of a label in a program:

```
$ nm -C ./password_checker | grep valid_password_encrypted
00000000004b6010 R valid_password_encrypted
```

Having that specific address in mind, we can boot up our favorite debugger and explore that area:

```
(gdb) x/32bx 0x00000000004b6010
0x4b6010 <valid_password_encrypted>:    0x34    0x2a    0x1f    0x31    0x0f       0x1f    0x27    0x30
0x4b6018 <valid_password_encrypted+8>:  0x0b    0x20    0x33    0x19    0x2d       0x34    0x31    0x03
0x4b6020 <valid_password_encrypted+16>: 0x29    0x27    0x3d    0x0d    0x39       0x09    0x31    0x00
0x4b6028:       0x45    0x6e    0x74    0x65    0x72    0x20    0x61    0x20
```

The password is a null-terminated string, and by looking at this output we know that it is 23 bytes long. Our final ciphertext is this:

```
34 2a 1f 31 0f 1f 27 30 0b 20 33 19 2d 34 31 03 29 27 3d 0d 39 09 31
```

Now, let's apply the inverse XOR-based transformation to every byte, concatenate the output, and print it as a string, using a simple Python script:

```python
encrypted = [
    0x34, 0x2a, 0x1f, 0x31, 0x0f, 0x1f, 0x27, 0x30,
    0x0b, 0x20, 0x33, 0x19, 0x2d, 0x34, 0x31, 0x03,
    0x29, 0x27, 0x3d, 0x0d, 0x39, 0x09, 0x31
]

def inverse_transform_char(t, i):
    return chr(((t ^ 0x55) - i) ^ 0x33)

password = ''.join(inverse_transform_char(t, i) for i, t in enumerate(encrypted))
print(password)
```

There we go!

```
$ python exploit.py 
RM{Rev_me_or_get_Revkt}
```
