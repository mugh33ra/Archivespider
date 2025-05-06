#!/bin/sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

tools=("go" "httpx" "uro")

for tool in "${tools[@]}"; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo -e "${RED}[>] $tool is not installed...${RESET}"
    sleep 0.5
    echo -e "${GREEN}[>] Installing $tool...⏳${RESET}"
    case "$tool" in
      go)
        echo -e "${YELLOW}[>] Installing Golang...⏳${RESET}"
        apt install golang -y
        ;;
      httpx)
        echo -e "${YELLOW}[>] Installing httpx...⏳${RESET}"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        cp ~/go/bin/subfinder /usr/bin/httpx-toolkit
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
    echo -e "${GREEN}[✓] $tool is already installed.${RESET}"
  fi
done
