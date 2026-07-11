# HellCat

A high–intensity VLESS/SS/TROJAN/HYSTERIA/VMESS pentesting-testing stress tool using xray-core and Go.

Use only in pentest your servers!

## Features

- Launch multiple xray-core instances automatically  
- Run hundreds of parallel HTTP download streams via SOCKS5  
- Config generation from VLESS links  
- Supports single `--url` or multiple via `--list`  

## Prerequisites

- Linux (tested on Ubuntu 22.04+)  
- `bash`, `curl`, `wget`, `unzip`  
- `git`  
- `sudo` privileges  

## Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/kitten443/hellcat_v3.git
   cd hellcat_v3
2. **Run the installer**  
   ```bash
    chmod +x install.sh
    ./install.sh
3. **Build the HellCat binary** 
   ```bash 
    go mod tidy
    go build -o hellcat main.go
