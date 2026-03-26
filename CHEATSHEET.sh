#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║           🤖 CTF Agent — Quick Reference                    ║
# ╚══════════════════════════════════════════════════════════════╝

# ──────────────────────────────────────────────────────────────
# 🎯 INTERACTIVE MODE (easiest — prompts for everything)
# ──────────────────────────────────────────────────────────────

python3 -m agent.main solve -i
python3 -m agent.main solve challenge.txt -i          # start with a file
python3 -m agent.main -v solve -i                     # verbose + interactive

# ──────────────────────────────────────────────────────────────
# ⚡ QUICK SOLVE (one-liner commands)
# ──────────────────────────────────────────────────────────────

# Basic — just a file
python3 -m agent.main solve challenge.txt

# With flag format (ALWAYS use this in competitions!)
python3 -m agent.main solve chall.txt -f "picoCTF\{.*?\}"
python3 -m agent.main solve chall.txt -f "HTB\{.*?\}"
python3 -m agent.main solve chall.txt -f "flag\{.*?\}"

# Force category (skips auto-detection, saves time)
python3 -m agent.main solve chall.txt -c crypto
python3 -m agent.main solve image.png  -c stego
python3 -m agent.main solve capture.pcap -c forensics
python3 -m agent.main solve binary.elf -c reversing
python3 -m agent.main solve vuln_binary -c pwn
python3 -m agent.main solve -u http://target:8080 -c web

# ──────────────────────────────────────────────────────────────
# 📝 PASSING CHALLENGE DESCRIPTIONS & HINTS
# ──────────────────────────────────────────────────────────────

# Short inline description
python3 -m agent.main solve chall.bin -d "Hint: the key is 13"

# Full description from a file (-D flag)
python3 -m agent.main solve chall.bin -D prompt.txt

# Pipe description (alternative)
python3 -m agent.main solve chall.bin -d "$(cat prompt.txt)"

# ──────────────────────────────────────────────────────────────
# 🏆 COMPETITION COMBO (fastest during CTFs)
# ──────────────────────────────────────────────────────────────

# Full power: verbose + category + flag format + description file
python3 -m agent.main -v solve challenge.zip \
  -c forensics \
  -f "picoCTF\{.*?\}" \
  -D challenge_prompt.txt

# Web challenge with URL
python3 -m agent.main -v solve \
  -u http://target.ctf.com:8080 \
  -c web \
  -f "CTF\{.*?\}" \
  -d "Login page, find the admin password"

# ──────────────────────────────────────────────────────────────
# 📦 BATCH SOLVE (multiple challenges at once)
# ──────────────────────────────────────────────────────────────

python3 -m agent.main batch challenges/*
python3 -m agent.main batch challenges/*.txt -f "flag\{.*?\}"

# ──────────────────────────────────────────────────────────────
# 🔧 UTILITY COMMANDS
# ──────────────────────────────────────────────────────────────

python3 -m agent.main scan                # check which tools are installed
python3 -m agent.main --help              # full help
python3 -m agent.main solve --help        # solve help

# ──────────────────────────────────────────────────────────────
# 💡 PRO TIPS
# ──────────────────────────────────────────────────────────────
#
# 1. ALWAYS use -f with the competition's flag format
# 2. Use -c if you know the category (saves 5-10 seconds)
# 3. Use -v to watch strategies in real-time
# 4. Use -D to pass full challenge descriptions from files
# 5. Use -i when you want a guided experience
# 6. Reports are auto-saved in reports/ (useful for writeups)
# 7. Drop challenge files in challenges/ to stay organized
#
# ──────────────────────────────────────────────────────────────
# 📋 CATEGORIES
# ──────────────────────────────────────────────────────────────
#
#  crypto     — encoding, ciphers, RSA, XOR
#  web        — SQL injection, LFI, JWT, source inspection
#  forensics  — file carving, PCAP, metadata, ZIP
#  reversing  — binary analysis, decompilation, angr
#  pwn        — buffer overflow, format strings, ROP
#  stego      — image/audio hidden data
#  misc       — encoding chains, QR codes, esoteric languages
#
