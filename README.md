# VulnScope Lite

VulnScope Lite is an integrated authorized-use security scanner that combines:

1. Reconnaissance
2. Reflected XSS checks
3. SQL injection checks
4. Security configuration checks

Only scan systems you own or are explicitly authorized to assess.

## Setup

```bash
on windoes:
python -m pip install -r requirements.txt
-----------------------------------------------------
Install on Kali

sudo apt update
sudo apt install python3 python3-venv python3-full nmap
sudo apt install ./vulcheck_1.0.0_all.deb

Then test:

vulcheck --help
vulcheck -t 192.168.64.129

The package installs the application under /opt/VulCheck and creates the
vulcheck command in /usr/local/bin.

Transfer to another Kali machine

Copy vulcheck_1.0.0_all.deb to the other machine, then run:

sudo apt update
sudo apt install python3 python3-venv python3-full nmap
sudo apt install ./vulcheck_1.0.0_all.deb

Important

The package currently contains the integrated Recon + Security Configuration
version. XSS and SQLi are represented by the integration layer as skipped
until their scanner modules are added.

Only scan systems you own or are explicitly authorized to assess.

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
