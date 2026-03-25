# 🤖 CTF Agent — Autonomous CTF Solver

An autonomous agent that analyzes, classifies, and solves Capture The Flag challenges using a combination of heuristics, external tools, and LLM reasoning.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure your LLM (copy and edit .env)
cp .env.example .env
# Edit .env with your API key

# 3. Solve a challenge
python -m agent.main solve challenges/my_challenge.txt

# 4. Check available tools
python -m agent.main scan
```

## Usage

### Solve a single challenge
```bash
# From a file
python -m agent.main solve challenge.zip

# From a URL (web challenges)
python -m agent.main solve -u http://target:8080

# With description
python -m agent.main solve challenge.bin -d "Find the hidden password"

# Force a category
python -m agent.main solve weird_file -c forensics

# Custom flag format
python -m agent.main solve chall.py -f "picoCTF\{.*?\}"

# Verbose mode
python -m agent.main -v solve challenge.png
```

### Batch solve
```bash
python -m agent.main batch challenges/*.txt
```

### Scan available tools
```bash
python -m agent.main scan
```

## Supported Categories

| Category | Strategies | Key Tools |
|----------|-----------|-----------|
| **Crypto** | Base64/hex decode, ROT brute, XOR attacks, RSA small-e/factoring, LLM | `sympy` |
| **Web** | Source inspection, robots.txt, SQLi, JWT tampering, LFI, directory brute | `requests`, `gobuster` |
| **Forensics** | Strings grep, EXIF, binwalk, foremost, PCAP analysis, ZIP cracking | `binwalk`, `exiftool`, `tshark` |
| **Reversing** | Strings, objdump, radare2, angr symbolic exec, Python decompile | `objdump`, `r2`, `angr` |
| **Pwn** | Checksec, format strings, buffer overflow, ROP chains | `pwntools` |
| **Stego** | zsteg, steghide, LSB manual, appended data, PNG chunks, spectrogram | `zsteg`, `steghide`, `Pillow` |
| **Misc** | Encoding chains, QR decode, morse code, brainfuck, number→ASCII, LLM | `pyzbar`, `Pillow` |

## Architecture

```
agent/
├── main.py          # CLI entry point
├── orchestrator.py  # analyze → route → solve → validate → report
├── analyzer.py      # file type + keyword + LLM classification
├── llm.py           # OpenAI-compatible LLM engine
├── tools.py         # safe subprocess execution
├── validator.py     # flag regex matching
├── reporter.py      # Markdown report generation
├── config.py        # configuration and constants
└── solvers/
    ├── base.py      # abstract strategy-based solver
    ├── crypto.py    # cryptography challenges
    ├── web.py       # web exploitation
    ├── forensics.py # forensics / file analysis
    ├── reversing.py # reverse engineering
    ├── pwn.py       # binary exploitation
    ├── stego.py     # steganography
    └── misc.py      # misc / OSINT / encoding
```

## How It Works

1. **Analyze** — Detects file type, scans for keywords, uses LLM for ambiguous cases
2. **Classify** — Routes to the best solver module (crypto, web, forensics, etc.)
3. **Solve** — Tries strategies in order of likelihood until a flag is found
4. **Validate** — Extracts flags using configurable regex patterns
5. **Report** — Generates a Markdown report in `reports/`

## Configuration

Copy `.env.example` to `.env` and set:

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | LLM API key | required |
| `OPENAI_BASE_URL` | API endpoint | `https://api.openai.com/v1` |
| `LLM_MODEL` | Model name | `gpt-4o` |
| `CTF_FLAG_FORMAT` | Default flag regex | `flag\{.*?\}` |
| `CTF_TIMEOUT` | Tool timeout (seconds) | `120` |
| `CTF_VERBOSE` | Verbose output | `false` |

## Optional External Tools

Install these for maximum capability (the agent gracefully skips missing tools):

```bash
# Forensics
sudo apt install binwalk foremost exiftool tshark

# Stego
gem install zsteg
sudo apt install steghide

# Reversing
sudo apt install radare2 objdump

# Audio
sudo apt install sox ffmpeg
```
