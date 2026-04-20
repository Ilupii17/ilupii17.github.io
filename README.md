# ~/ctf-writeups-theme

Tema Jekyll untuk blog CTF Write-ups dengan desain Sport-Pop Modern Aesthetic.

## ✨ Fitur

- 🌙 **Dark/Light Mode** — toggle instan, persisten via localStorage
- 🎨 **Design Timbul** — efek elevated button & card sesuai desain asli
- 🖥️ **Terminal Aesthetic** — syntax highlighting berdesain terminal console
- 📋 **Table of Contents** — sticky di desktop, accordion di mobile
- ⏱️ **CTF Timeline** — halaman vertikal timeline dari file YAML
- 📱 **Responsive** — optimal di semua ukuran layar
- ⚡ **Zero JS framework** — hanya Vanilla JS ringan

## 📁 Struktur File

```
.
├── _config.yml              # Konfigurasi Jekyll
├── _data/
│   └── timeline.yml         # Data riwayat CTF
├── _includes/
│   ├── header.html          # Header + navigasi
│   └── modal.html           # Modal menu
├── _layouts/
│   ├── default.html         # Layout utama (wrapper)
│   └── post.html            # Layout artikel write-up + ToC
├── _posts/                  # File Markdown write-up kamu
│   └── YYYY-MM-DD-judul.md
├── _sass/
│   ├── _variables.scss      # Warna & design tokens
│   ├── _base.scss           # Reset, tipografi, grid background
│   └── _components.scss     # Semua komponen UI
├── assets/
│   └── css/
│       └── main.scss        # Entry point SCSS
├── index.html               # Halaman beranda
└── timeline.html            # Halaman CTF Timeline
```

## 🚀 Setup & Deploy

### 1. Clone & Install

```bash
git clone https://github.com/USERNAME/ctf-writeups
cd ctf-writeups
bundle install
```

### 2. Jalankan Lokal

```bash
bundle exec jekyll serve --livereload
# Buka http://localhost:4000
```

### 3. Deploy ke GitHub Pages

1. Push ke repo GitHub
2. Buka **Settings → Pages**
3. Set source ke **branch `main`, folder `/root`**
4. Done! GitHub Pages akan otomatis build Jekyll

## ✍️ Cara Tambah Write-up

Buat file baru di `_posts/` dengan format:

```
_posts/YYYY-MM-DD-nama-challenge.md
```

**Front matter yang tersedia:**

```yaml
---
layout: post
title: "Nama Challenge"
categories: [Pwn]          # Pwn | Web | Rev | Misc | Crypto | Forensics
tags: [heap, UAF, libc]    # Tag bebas
date: 2025-01-01 10:00:00 +0700
author: kali@wsl2
ctf_event: "Nama CTF"      # Ditampilkan di kartu & header post
difficulty: Hard            # Easy | Medium | Hard | Insane
excerpt: "Deskripsi singkat untuk preview di kartu beranda."
---

* TOC
{:toc}

## Isi write-up kamu di sini...
```

> **Penting**: `* TOC\n{:toc}` **wajib** ada di awal konten agar ToC auto-generated oleh kramdown dan dipindahkan oleh JavaScript ke sidebar/accordion.

## ⏱️ Cara Tambah Timeline CTF

Edit file `_data/timeline.yml`:

```yaml
- nama_ctf: "Nama CTF Event"
  tanggal: "2025-09-15"
  rank: "12th / 500 teams"
  platform: "CTFd"
  kategori:
    - Pwn
    - Web
  highlight: "Deskripsi singkat apa yang berhasil di-solve."
  url: "https://ctftime.org/event/XXXX"
  warna: pwn   # pwn | web | rev | misc
```

## 🎨 Kustomisasi Warna

Edit `_sass/_variables.scss` bagian `:root` untuk light mode
dan `[data-theme="dark"]` untuk dark mode.

Warna aksen utama:
- `--accent-main` — Kuning/Amber (default heading, cursor)
- `--accent-teal` — Teal (web cards, ToC active, links)
- `--accent-orange` — Oranye (pwn cards, danger buttons)
- `--accent-lime` — Lime (rev cards, terminal prompt)

## 📄 Lisensi

MIT — bebas dipakai dan dimodifikasi.

---

## ⚠️ Tips Penting: Liquid Tag Conflict

Jekyll menggunakan Liquid templating. Karena itu, karakter `{{`, `}}`, `{%`, dan `%}` di dalam file Markdown **akan diproses oleh Liquid** dan menyebabkan error build jika tidak valid.

**Ini sering terjadi di CTF write-up** karena banyak payload (SSTI, Jinja2, Twig, Thymeleaf, dll) mengandung karakter tersebut.

### Solusi: Gunakan `{% raw %}...{% endraw %}`

Wrap semua blok kode yang mengandung `{{`, `}}`, `{%`, atau `%}` dengan tag ini:

````markdown
{% raw %}
```java
// Payload SSTI Thymeleaf — aman dari Liquid
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```
{% endraw %}
````

### Karakter yang wajib di-escape dengan `raw`:

| Karakter | Contoh payload | Kategori |
|----------|---------------|----------|
| `{{` `}}` | Jinja2, Twig, Thymeleaf, Go template | Web/SSTI |
| `{%` `%}` | Jinja2, Twig, Django template | Web/SSTI |
| `{#` `#}` | Nunjucks, Thymeleaf comment | Web/SSTI |

Blok kode tanpa karakter-karakter di atas (Pwn, Rev, Python biasa, C, assembly) **tidak perlu** dibungkus `raw`.
