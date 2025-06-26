#!/bin/bash

# Color and Style Variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# API Keys
VT_API_KEY="845a78a30376b485ce0c66d28c41f38712bc6becf2a628a9d464d1c3c5a8f718"

# Banner Function
banner() {
    echo -e "${BLUE}${BOLD}"
    echo "   ___           __   _          ____     _    __       "
    echo "  / _ | ________/ /  (_)  _____ / __/__  (_)__/ /__ ____"
    echo " / __ |/ __/ __/ _ \/ / |/ / -_)\ \/ _ \/ / _  / -_) __/"
    echo "/_/ |_/_/  \__/_//_/_/|___/\__/___/ .__/_/\_,_/\__/_/   "
    echo -e "                                 /_/${NC}                    "
    echo -e "${MAGENTA}${BOLD}                  ArchiveSpider - Web Archive & IP Scanner${NC}"
    echo -e "${CYAN}${BOLD}                  Coded By mugh33ra (@mugh33ra)${NC}"
    echo -e "${MAGENTA}${BOLD}==============================================================${NC}\n"
}

# Usage Function
usage() {
    echo -e "${YELLOW}${BOLD}Usage:${NC} $0 -d domain.com [options]\n"
    echo -e "${YELLOW}${BOLD}Options:${NC}"
    echo -e "  -d, --domain <domain>        Target domain (required)"
    echo -e "  -m, --mode <mode>            Operation mode:"
    echo -e "                               sd - Single domain (default)"
    echo -e "                               wc - Wildcard (include subdomains)"
    echo -e "  -ips                         Extract Origin IPs from AlienVault & Virus_Total"
    echo -e "  -o, --output <directory>     Custom output directory"
    echo -e "  -up, --update                Update script to latest version"
    echo -e "  -h, --help                   Show this help message"
    exit 0
}

# Update Function
update_script() {
    echo -e "\n${MAGENTA}${BOLD}➤ Updating ArchiveSpider${NC}"
    echo -e "${CYAN}${BOLD}├─ Downloading latest version...${NC}"
    
    # Get the directory where the script is located
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    script_name="$(basename "${BASH_SOURCE[0]}")"
    script_path="${script_dir}/${script_name}"
    tmp_file="${script_dir}/.${script_name}.tmp"
    
    # Download the new version
    if ! curl -s "https://raw.githubusercontent.com/mugh33ra/Archive-Data/main/Archivespider.sh" -o "$tmp_file"; then
        echo -e "${RED}${BOLD}✖ Failed to download update${NC}"
        rm -f "$tmp_file" 2>/dev/null
        return 1
    fi
    
    # Verify the downloaded script
    if ! grep -q "ArchiveSpider" "$tmp_file"; then
        echo -e "${RED}${BOLD}✖ Downloaded file doesn't appear to be valid${NC}"
        rm -f "$tmp_file" 2>/dev/null
        return 1
    fi
    
    # Make backup of current version
    cp "$script_path" "${script_path}.bak"
    
    # Replace the script
    if ! mv "$tmp_file" "$script_path"; then
        echo -e "${RED}${BOLD}✖ Failed to replace script${NC}"
        return 1
    fi
    
    chmod +x "$script_path"
    echo -e "${GREEN}${BOLD}✔ Successfully updated ArchiveSpider${NC}"
    
    # Ask user if they want to restart
    read -p "Update complete. Restart script now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}${BOLD}└─ Restarting...${NC}"
        rm  $0.bak
        exec "$script_path" "${original_args[@]}"
    else
        echo -e "${CYAN}${BOLD}└─ Changes will take effect on next run${NC}"
        rm  $0.bak
        exit 0
    fi
}

# Trap Ctrl+C
trap ctrl_c INT

ctrl_c() {
    echo -e "\n\n${RED}${BOLD}[!] Ctrl+C detected${NC}"
    read -p "Are you sure you want to skip this process? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}${BOLD}[*] Skipping current process...${NC}"
        continue_process=true
    else
        echo -e "${GREEN}${BOLD}[*] Resuming current process...${NC}"
        continue_process=false
    fi
}

# Spinner Animation
show_spinner() {
    local pid=$!
    local message="${1:-Processing}"
    local spin=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        if [[ $continue_process == true ]]; then
            kill -9 "$pid" 2>/dev/null
            return 1
        fi
        i=$(( (i+1) %8 ))
        printf "\r${CYAN}${BOLD}[${spin[$i]}]${NC} ${BLUE}${message}...${NC}"
        sleep 0.1
    done
    printf "\r${GREEN}${BOLD}[✓]${NC} ${GREEN}${message} completed!${NC}       \n"
}

# Wayback Machine Function
wayback() {
    echo -e "\n${MAGENTA}${BOLD}➤ Wayback Machine Data Collection${NC}"
    
    local url_patterns=("$domain/*")
    if [[ $wildcard_mode ]]; then
        url_patterns=("*.$domain/*" "*.*.$domain/*")
        echo -e "${CYAN}${BOLD}├─ Mode:${NC} Wildcard (*.$domain and *.*.$domain)"
    else
        echo -e "${CYAN}${BOLD}├─ Mode:${NC} Single domain ($domain)"
    fi
    
    echo -e "${CYAN}${BOLD}├─ Extracting URLs from Wayback CDX...${NC}"
    
    for pattern in "${url_patterns[@]}"; do
        echo -e "${CYAN}${BOLD}├─ Pattern: ${pattern}${NC}"
        curl -s "https://web.archive.org/cdx/search/cdx?url=$pattern&collapse=urlkey&output=text&fl=original" >> cdx.txt &
        show_spinner "Fetching pattern $pattern"
        if [[ $continue_process == true ]]; then
            continue_process=false
            break
        fi
    done
    
    if [[ ! -s cdx.txt ]]; then
        echo -e "${RED}${BOLD}✖ No data found in Wayback Machine${NC}"
        rm -f cdx.txt
    else
        cat cdx.txt | sort -u > tmp_cdx && mv tmp_cdx waybackdata.txt && rm -f cdx.txt
        total=$(wc -l < waybackdata.txt)
        echo -e "${GREEN}${BOLD}✔ Found ${total} URLs${NC}"
        echo -e "${BLUE}${BOLD}└─ Saved to waybackdata.txt${NC}"
    fi
}

# Alien Vault Function with pagination
otx_alienvault() {
    echo -e "\n${MAGENTA}${BOLD}➤ Alien Vault OTX Data Collection${NC}"
    
    local max_pages=6
    local otx_url
    local target_domain="$domain"
    
    # Extract root domain if wildcard mode and subdomain is provided
    if [[ $mode == "wc" && $domain == *.*.* ]]; then
        target_domain=$(echo "$domain" | awk -F'.' '{print $(NF-1)"."$NF}')
        echo -e "${CYAN}${BOLD}├─ Converted to root domain: $target_domain${NC}"
    fi
    
    if [[ $mode == "wc" ]]; then
        otx_url="https://otx.alienvault.com/api/v1/indicators/domain/${target_domain}/url_list?limit=500"
        echo -e "${CYAN}${BOLD}├─ Mode:${NC} Wildcard (*.$target_domain) with pagination (max ${max_pages} pages)"
    else
        otx_url="https://otx.alienvault.com/api/v1/indicators/hostname/${target_domain}/url_list?limit=500"
        echo -e "${CYAN}${BOLD}├─ Mode:${NC} Single domain ($target_domain)"
    fi
    
    echo -e "${CYAN}${BOLD}├─ Fetching URLs from Alien Vault...${NC}"
    
    if [[ $mode == "wc" ]]; then
        for ((page=1; page<=$max_pages; page++)); do
            echo -e "${CYAN}${BOLD}├─ Fetching page ${page}...${NC}"
            curl -s "${otx_url}&page=${page}" >> alienVault.txt &
            show_spinner "Fetching page ${page}"
            if [[ $continue_process == true ]]; then
                continue_process=false
                break
            fi
            
            # Check if we got less than 500 results (likely last page)
            if [[ $(wc -l < alienVault.txt) -lt $((page * 500)) ]]; then
                break
            fi
        done
    else
        curl -s "$otx_url" > alienVault.txt &
        show_spinner "Fetching from Alien Vault API"
    fi
    
    if [[ $continue_process == true ]]; then
        continue_process=false
        return
    fi
    
    if [[ ! -s alienVault.txt ]]; then
        echo -e "${RED}${BOLD}✖ No data found in Alien Vault${NC}"
        rm -f alienVault.txt
    else
        cat alienVault.txt | sort -u | jq -r '.url_list[]?.url' > alien.txt && \
        rm -f alienVault.txt && mv alien.txt alienVault.txt
        total=$(wc -l < alienVault.txt)
        echo -e "${GREEN}${BOLD}✔ Found ${total} URLs${NC}"
        echo -e "${BLUE}${BOLD}└─ Saved to alienVault.txt${NC}"
    fi
}

# VirusTotal Function
vt_data() {
    echo -e "\n${MAGENTA}${BOLD}➤ VirusTotal Data Collection${NC}"
    echo -e "${CYAN}${BOLD}├─ Fetching URLs from VirusTotal...${NC}"
    
    curl -s "https://virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$VT_API_KEY" > vt.txt &
    show_spinner "Fetching from VirusTotal API"
    if [[ $continue_process == true ]]; then
        continue_process=false
        return
    fi
    
    if [[ ! -s "vt.txt" ]]; then
        echo -e "${RED}${BOLD}✖ No data found in VirusTotal${NC}"
        rm -f vt.txt
    else
        cat vt.txt | sort -u | jq -r '.. | strings | select(test("https?://"))' | \
        grep -E '(https?://[^\s"<>]+)' | grep "${domain}" > vt-urls.txt
        rm -f vt.txt && mv vt-urls.txt vt.txt
        total=$(wc -l < vt.txt)
        echo -e "${GREEN}${BOLD}✔ Found ${total} URLs${NC}"
        echo -e "${BLUE}${BOLD}└─ Saved to vt.txt${NC}"
    fi
}

# IP Scanning Functions (silent version)
fetch_vt_ips() {
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$VT_API_KEY" \
        | jq -r '.. | .ip_address? // empty' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

fetch_otx_ips() {
    curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/url_list?limit=500&page=1" \
        | jq -r '.url_list[]?.result?.urlworker?.ip // empty' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

fetch_url_scan() {
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" \
        | jq -r '.results[]?.page?.ip // empty' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

ip_scan() {
    echo -e "\n${MAGENTA}${BOLD}➤ IP Address Discovery${NC}"
    echo -e "${CYAN}${BOLD}├─ Scanning: ${GREEN}Wayback, AlienVault & UrlScan.io${NC}"
    
    local output_file="${domain}_ips.txt"
    
    # Show single spinner for all IP fetching
    (
        fetch_vt_ips
        fetch_otx_ips
        fetch_url_scan
    ) | sort -u | tee "$output_file" &
    show_spinner "Fetching IP addresses"
    
    if [[ $continue_process == true ]]; then
        continue_process=false
        return
    fi
    
    if [[ ! -s "$output_file" ]]; then
        echo -e "${RED}${BOLD}✖ No IPs found for $domain${NC}"
        rm -f "$output_file"
    else
        count=$(wc -l < "$output_file")
        echo -e "${GREEN}${BOLD}✔ Found $count unique IP addresses${NC}"
        echo -e "${BLUE}${BOLD}└─ Saved to $output_file${NC}"
    fi
}

# Filtering Function
filter_data() {
    echo -e "\n${MAGENTA}${BOLD}➤ Data Processing${NC}"
    
    if [[ -f "waybackdata.txt" && -f "alienVault.txt" && -f "vt.txt" ]]; then
        echo -e "${CYAN}${BOLD}├─ Filtering for interesting files...${NC}"
        cat waybackdata.txt alienVault.txt vt.txt | sort -u | \
        grep -E '\.(xls|xml|xlsx|json|pdf|sql|docx?|pptx|txt|zip|targz|tgz|gz|bak|7z|rar|log|cache|secret|db|backup|yml|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|py|tar|deb|rpm|iso|img|apk|msi|dmg|tmp|crt|pem|key|pub|asc)' > tmp_juicy.txt
        
        grep -v "\.js" tmp_juicy.txt > juicy.txt && rm -f tmp_juicy.txt
        echo -e "${GREEN}${BOLD}├─ Interesting files saved to juicy.txt${NC}"
        
        echo -e "${CYAN}${BOLD}├─ Combining all URLs...${NC}"
        cat waybackdata.txt alienVault.txt vt.txt | sort -u > allurls.txt
        
        if [[ ! -d ".backup" ]]; then 
            mkdir -p .backup
        fi
        mv waybackdata.txt alienVault.txt vt.txt .backup/
        
        echo -e "${CYAN}${BOLD}├─ Removing media/static files...${NC}"
        cat allurls.txt | grep -vE '\.jpg|\.png|\.jpeg|\.gif|\.woff|\.ts|\.webp|\.css|\.ttf|\.svg|\.swf|\.eot|\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.targz|\.tgz|\.gz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.py|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc$' | uro > cleanUrls.txt
        rm -f allurls.txt
        
        echo -e "${GREEN}${BOLD}✔ Data processing complete!${NC}"
    else
        echo -e "${RED}${BOLD}✖ Required files are missing${NC}"
        exit 1
    fi
}

# JavaScript Filtering
filter_js() {
    echo -e "\n${MAGENTA}${BOLD}➤ JavaScript Files Processing${NC}"
    
    if [[ -f "cleanUrls.txt" ]]; then
        echo -e "${CYAN}${BOLD}├─ Filtering JavaScript files...${NC}"
        cat cleanUrls.txt | sort -u | grep "\.js$" > js.txt
        
        if [[ -s "js.txt" ]]; then
            cat cleanUrls.txt | sort -u | grep -v "\.js" > tmp_clean.txt
            mv tmp_clean.txt cleanUrls.txt
            total_js=$(wc -l < js.txt)
            echo -e "${GREEN}${BOLD}├─ Found ${total_js} JavaScript files${NC}"
            echo -e "${BLUE}${BOLD}└─ Saved to js.txt${NC}"
        else
            rm -f js.txt
            echo -e "${YELLOW}${BOLD}⚠ No JavaScript files found${NC}"
        fi
    else
        echo -e "${RED}${BOLD}✖ cleanUrls.txt is missing${NC}"
    fi
}

# HTTPX Processing
process_httpx() {
    echo -e "\n${MAGENTA}${BOLD}➤ HTTPX Processing${NC}"
    
    if [[ -f "js.txt" ]]; then
        echo -e "${CYAN}${BOLD}├─ Running httpx on JS files...${NC}"
        if command -v httpx-toolkit &>/dev/null; then
            cat js.txt | httpx-toolkit --status-code > js1.txt
            cat js1.txt | grep "200" | cut -d "[" -f 1 > alivejs.txt
            rm -f js1.txt
            
            echo -e "${CYAN}${BOLD}├─ Extracting endpoints...${NC}"
            cat alivejs.txt | while read url; do 
                curl -s "$url" | grep -Eo '(/[a-zA-Z0-9_-]+)*)|(/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*)\.(php|aspx|asp|jsp|html|json|sql|ini|log|LOG|xml|zip|conf|htm|jspx|cgi|bak|backup)' | \
                tr -d '"' | sort -u | cut -d ")" -f 1
            done > endpoints.txt
            
            echo -e "${GREEN}${BOLD}✔ Endpoints saved to endpoints.txt${NC}"
        else
            echo -e "${RED}${BOLD}✖ httpx-toolkit not found${NC}"
        fi
    else
        echo -e "${RED}${BOLD}✖ js.txt not found${NC}"
    fi
}

# Summary Function
show_summary() {
    echo -e "\n${MAGENTA}${BOLD}➤ Final Summary${NC}"
    
    if [[ -f "cleanUrls.txt" ]]; then
        clean_count=$(wc -l < cleanUrls.txt)
        echo -e "${CYAN}${BOLD}├─ Clean URLs: ${GREEN}${clean_count}${NC} (cleanUrls.txt)"
    fi
    
    if [[ -f "js.txt" ]]; then
        js_count=$(wc -l < js.txt)
        echo -e "${CYAN}${BOLD}├─ JavaScript Files: ${GREEN}${js_count}${NC} (js.txt)"
    fi
    
    if [[ -f "juicy.txt" ]]; then
        juicy_count=$(wc -l < juicy.txt)
        echo -e "${CYAN}${BOLD}├─ Interesting Files: ${GREEN}${juicy_count}${NC} (juicy.txt)"
    fi
    
    if [[ -f "endpoints.txt" ]]; then
        endpoints_count=$(wc -l < endpoints.txt)
        echo -e "${CYAN}${BOLD}├─ Extracted Endpoints: ${GREEN}${endpoints_count}${NC} (endpoints.txt)"
    fi
    
    echo -e "\n${GREEN}${BOLD}✔ All operations completed successfully!${NC}"
    echo -e "${BLUE}${BOLD}  Results saved in the ${domain}/ directory${NC}\n"
}

# Main Execution
main() {
    banner
    
    # Default values
    mode="sd"
    ip_scanning=false
    full_scan=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                domain=$(echo "$2" | sed 's|https://||;s|http://||;s|/||')
                shift 2
                ;;
            -m|--mode)
                if [[ "$2" == "wc" || "$2" == "sd" ]]; then
                    mode="$2"
                else
                    echo -e "${RED}${BOLD}[!] Invalid mode. Use 'sd' (single domain) or 'wc' (wildcard)${NC}"
                    exit 1
                fi
                shift 2
                ;;
            -ips|--ip-scan)
                ip_scanning=true
                full_scan=true  # Enable full scan when -ips is used
                shift
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -up|--update)
                update_script "$@"
                exit $?
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}${BOLD}[!] Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate domain
    if [[ -z $domain ]]; then
        echo -e "${RED}${BOLD}[!] Domain is required${NC}"
        usage
        exit 1
    fi
    
    if ! [[ $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}${BOLD}[!] Please enter a valid domain (e.g. example.com)${NC}"
        exit 1
    fi
    
    # Set wildcard_mode based on mode
    if [[ $mode == "wc" ]]; then
        wildcard_mode=true
    fi
    
    # Create output directory
    if [[ -n $output_dir ]]; then
        if [[ ! -d "$output_dir" ]]; then
            mkdir -p "$output_dir"
        fi
        cd "$output_dir" || exit
    elif [[ ! -d "$domain" ]]; then
        mkdir -p "$domain" && cd "$domain" || exit
    else
        cd "$domain" || exit
    fi
    
    # Reset continue process flag
    continue_process=false
    
    # If only IP scan requested
    if [[ $ip_scanning == true && $full_scan == false ]]; then
        ip_scan
        exit 0
    fi
    
    # Execute main functions
    wayback
    otx_alienvault
    vt_data
    
    # Enhanced IP scanning with all collected data
    if [[ $ip_scanning == true ]]; then
        echo -e "\n${MAGENTA}${BOLD}➤ Enhanced IP Address Discovery${NC}"
        echo -e "${CYAN}${BOLD}├─ Scanning: ${GREEN}All Collected URLs + External Sources${NC}"
        
        # Extract IPs from all collected URLs first
        local ip_file="${domain}_ips.txt"
        
        # Extract IPs from URLs
        {
            # From collected URLs
            if [[ -f "waybackdata.txt" ]]; then
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' waybackdata.txt
            fi
            if [[ -f "alienVault.txt" ]]; then
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' alienVault.txt
            fi
            if [[ -f "vt.txt" ]]; then
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' vt.txt
            fi
            
            # From external sources
            fetch_vt_ips
            fetch_otx_ips
            fetch_url_scan
        } | sort -u | tee "$ip_file" &
        show_spinner "Extracting IPs from all sources"
        
        if [[ ! -s "$ip_file" ]]; then
            echo -e "${RED}${BOLD}✖ No IPs found for $domain${NC}"
            rm -f "$ip_file"
        else
            count=$(wc -l < "$ip_file")
            echo -e "${GREEN}${BOLD}✔ Found $count unique IP addresses${NC}"
            echo -e "${BLUE}${BOLD}└─ Saved to $ip_file${NC}"
        fi
    fi
    
    # Continue with remaining processing
    filter_data
    filter_js
    process_httpx
    show_summary
}

main "$@"
