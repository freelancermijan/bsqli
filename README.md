## Installation

```
cd /opt/ && sudo git clone https://github.com/freelancermijan/bsqli.git && cd bsqli/
sudo chmod +x ./*.py
cd

sudo apt install dos2unix -y

sudo dos2unix /opt/bsqli/bsqli.py

sudo ln -sf /opt/bsqli/bsqli.py /usr/local/bin/bsqli

bsqli -h
```

### Options

```
usage: bsqli [-h] -u URLS -p PAYLOADS [-c COOKIE] [-t THREADS] [-o SAVE] [-v] [-V]

BSQLI Tool - One Line Command Tool

options:
  -h, --help            show this help message and exit
  -u URLS, --urls URLS  Path to URL list file or a single URL
  -p PAYLOADS, --payloads PAYLOADS
                        Path to the payload file
  -c COOKIE, --cookie COOKIE
                        Cookie to include in GET request
  -t THREADS, --threads THREADS
                        Number of concurrent threads (0-10)
  -o SAVE, --save SAVE  Filename to save vulnerable URLs
  -v, --verbose         Enable verbose mode
  -V, --version         show program's version number and exit
```

<a href="https://github.com/freelancermijan/my-payloads/blob/main/SQLi/Blind-SQLis/sleeps.txt"></a>

### sleep payload

```
wget https://raw.githubusercontent.com/freelancermijan/my-payloads/refs/heads/main/SQLi/Blind-SQLis/sleeps.txt
```

## Features

1. Multi Parameter scanning.
2. Others

![multi-parameter](multi-parameter.png)
