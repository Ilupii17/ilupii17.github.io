source "https://rubygems.org"

# Jekyll versi yang kompatibel dengan GitHub Pages
gem "github-pages", group: :jekyll_plugins

# Atau jika deploy mandiri (bukan GitHub Pages):
# gem "jekyll", "~> 4.3"

group :jekyll_plugins do
  gem "jekyll-feed"
  gem "jekyll-seo-tag"
  # Opsional: uncomment jika ingin server-side ToC
  # gem "jekyll-toc"
end

# Windows & JRuby compatibility
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# wdm 0.2.x kompatibel dengan Ruby 3.x di Windows
# wdm 0.1.1 TIDAK kompatibel dengan Ruby 3.4 — jangan pakai versi lama
gem "wdm", ">= 0.2.0", platforms: [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", platforms: [:jruby]
