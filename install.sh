#!/bin/sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

tools=("go" "httpx-toolkit" "uro")

for tool in "${tools[@]}"; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo -e "${RED}[>] $tool is not installed...${RESET}"
    sleep 0.5
    case "$tool" in
      go)
        echo -e "${YELLOW}[>] Installing Golang...⏳${RESET}"
        apt install golang -y
        ;;
      httpx-toolkit)
        echo -e "${YELLOW}[>] Installing httpx...⏳${RESET}"
        wget "https://github.com/projectdiscovery/httpx/releases/download/v1.7.0/httpx_1.7.0_linux_amd64.zip" -O httpx.zip
        unzip httpx.zip && chmod +x * && mv httpx /usr/local/bin/httpx-toolkit && rm httpx.zip
        ;;
      uro)
        echo -e "${YELLOW}[>] Installing uro...⏳${RESET}"
        pip3 install uro
        ;;
      *)
        echo -e "${YELLOW}[!] No install logic for $tool. Skipping...${RESET}"
        ;;
    esac
  else
    sleep 1
    echo -e "${GREEN}[✓] $tool is already installed.${RESET}"
  fi
done
