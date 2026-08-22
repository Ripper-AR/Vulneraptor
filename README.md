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
on linux:
1. Copy your project to /opt

If your project is currently:

~/VulCheck

run:

sudo mkdir -p /opt/VulCheck
sudo cp -r ~/VulCheck/* /opt/VulCheck/

Check:

ls /opt/VulCheck
2. Create the virtual environment
cd /opt/VulCheck
sudo apt update
sudo apt install python3-venv python3-full

Then:

sudo python3 -m venv /opt/VulCheck/.venv

Install your dependencies:

sudo /opt/VulCheck/.venv/bin/python -m pip install --upgrade pip
sudo /opt/VulCheck/.venv/bin/python -m pip install -r /opt/VulCheck/requirements.txt

This avoids Kali's externally-managed-environment problem.

3. Make main.py executable through a global command

Create:

sudo nano /usr/local/bin/VulCheck

Put this inside:

#!/bin/bash


exec /opt/VulCheck/.venv/bin/python /opt/VulCheck/main.py "$@"

Save:

CTRL+O
ENTER
CTRL+X

Then:

sudo chmod +x /usr/local/bin/VulCheck
4. Test the command

Now you should be able to run:

VulCheck

or:

VulCheck 192.168.64.129

or, depending on your main.py CLI:

VulCheck --target 192.168.64.129

The important part is that you don't need to activate .venv.

5. Make sure Nmap is available

Since your current integrated Recon version is using Nmap, install it normally through Kali:

sudo apt update
sudo apt install nmap

Check:

nmap --version

Then:

VulCheck 192.168.64.129

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
