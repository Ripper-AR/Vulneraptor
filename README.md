# VulnScope Lite

VulnScope Lite is an integrated authorized-use security scanner that combines:

1. Reconnaissance
2. Reflected XSS checks
3. SQL injection checks
4. Security configuration checks

Only scan systems you own or are explicitly authorized to assess.

## Setup

```bash
python -m pip install -r requirements.txt
```

Recon uses `python-nmap`, which also requires the Nmap binary to be installed
and available in your system path.

## Usage

```bash
python main.py 192.168.64.129
python main.py http://lab.local --json reports/scan.json
python main.py --target-file targets.txt --json reports/batch.json
```

## Tests

```bash
python -m pytest -q
```
