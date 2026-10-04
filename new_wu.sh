#!/bin/bash

# Pastikan script dijalankan di root direktori blog
if [ ! -d "_posts" ]; then
  echo "❌ Error: Tolong jalankan script ini dari root direktori blog (tempat folder _posts berada)."
  exit 1
fi

echo "========================================"
echo "   🚀 Quick Write-up Generator 🚀"
echo "========================================"

# Hanya minta input judul
read -p "Masukkan Judul Write-up: " title

# Cegah input kosong
if [ -z "$title" ]; then
  echo "❌ Error: Judul tidak boleh kosong!"
  exit 1
fi

# Generate tanggal & slug
date_filename=$(date +"%Y-%m-%d")
date_frontmatter=$(date +"%Y-%m-%d %H:%M:%S %z")
slug=$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9]/-/g' | sed -e 's/-\+/-/g' | sed -e 's/^-//' | sed -e 's/-$//')

# Path file lengkap
filepath="_posts/${date_filename}-${slug}.md"

# Cek apakah file sudah ada
if [ -f "$filepath" ]; then
  echo "⚠️ Warning: File $filepath sudah ada!"
  exit 1
fi

# Tulis template ke file (dibuat tanpa indentasi agar rapi)
cat <<EOF > "$filepath"
---
layout: post
title: "$title"
categories: []
tags: []
date: $date_frontmatter
author: kali@wsl2
ctf_event: ""
difficulty: ""
excerpt: ""
---

* TOC
{:toc}

# tes

EOF

echo "✅ Berhasil! File write-up baru telah dibuat di:"
echo "   ➡️  $filepath"