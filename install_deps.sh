#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║           🤖 CTF Agent — Tool Installation Script            ║
# ╚══════════════════════════════════════════════════════════════╝
# This script installs the external CLI tools used by the agent
# intended for Kali Linux / Debian / Ubuntu.

set -e

echo "[*] Updating apt package lists..."
sudo apt-update || sudo apt update

echo "[*] Installing core forensics and stego tools..."
sudo apt install -y \
    binwalk \
    exiftool \
    ffmpeg \
    foremost \
    steghide \
    sox \
    tshark \
    file \
    strings

echo "[*] Installing web and networking tools..."
sudo apt install -y \
    ffuf \
    gobuster \
    nmap \
    sqlmap

echo "[*] Installing binaries/reversing/crypto tools..."
sudo apt install -y \
    gdb \
    john \
    hashcat \
    radare2 \
    binutils  # provides objdump

echo "[*] Installing Ruby (needed for zsteg)..."
sudo apt install -y ruby-full
echo "[*] Installing zsteg..."
sudo gem install zsteg || echo "[!] Failed to install zsteg via gem. Try 'sudo apt install zsteg' if available."

echo "[*] Installing volatility3..."
# Usually volatility is better run via pipx or pre-installed in Kali,
# but we'll ensure python3-volatility3 is installed if in apt
sudo apt install -y volatility3 || echo "[!] volatility3 not in apt, install via pipx: pipx install volatility3"

echo ""
echo "✅ All system tools installed!"
echo "Run: 'python3 -m agent.main scan' to verify."
