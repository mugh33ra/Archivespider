#!/bin/bash


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
MAGENTA='\033[0;35m'
NC="\e[0m"
BOLD='\033[1m'
CYAN='\033[0;36m'

domain=$1
apikey=845a78a30376b485ce0c66d28c41f38712bc6becf2a628a9d464d1c3c5a8f718



# ========== 🧾 Banner ==========
banner() {
echo -e "${MAGENTA}${BOLD}"
cat << "EOF"
     _             _     _                  ____        _        
    / \   _ __ ___| |__ (_) _____   _____  |  _ \  __ _| |_ __ _ 
   / _ \ | '__/ __| '_ \| |/ _ \ \ / / _ \ | | | |/ _` | __/ _` |
  / ___ \| | | (__| | | | |  __/\ V /  __/ | |_| | (_| | || (_| |
 /_/   \_\_|  \___|_| |_|_|\___| \_/ \___| |____/ \__,_|\__\__,_|

                   🚀 Coded By @mugh33ra(x) 
EOF
echo -e "${NC}"
}

# ========== 📌 Usage ==========
if [[ $# != 1 ]]; then
    banner
    echo -e "${YELLOW}${BOLD}⚠️ Usage: $0 example.com 😒${NC}"
    exit 1
else
    banner
fi

if [[ ! -d $domain ]]; then
	mkdir $domain && cd $domain
fi

show_spinner() {
    local pid=$!
    local message="${1:-Processing}"
    local spin='-\|/'; local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${YELLOW}${BOLD}[*] $message... ${spin:$i:1}"
        sleep 0.1
    done
    printf "\r[✓] $message completed!       \n"
}





run_cdx() {

    echo -e "${MAGENTA}${BOLD}
	┓ ┏    ┳┓   ┓   ┳┓     
	┃┃┃┏┓┓┏┣┫┏┓┏┃┏  ┃┃┏┓╋┏┓
	┗┻┛┗┻┗┫┻┛┗┻┗┛┗  ┻┛┗┻┗┗┻
	      ┛                
${NC}"
	local update_interval=100
	local count=0
    echo -e "${YELLOW}${BOLD}[+] Extracting URLs from Wayback CDX...⏳${NC}"

    # Start curl in background and show spinner
    curl -s "https://web.archive.org/cdx/search/cdx?url=$domain/*&collapse=urlkey&output=text&fl=original" > cdx.txt &
    show_spinner "${YELLOW}${BOLD} Fetching from CDX Api"

    if [[ ! -s cdx.txt ]]; then
    	echo -e "${RED}${BOLD}[!] cdx.txt is empty😥${NC}"
    	echo -e "${RED}${BOLD}[+] Removing cdx.txt...⏳${NC}"
    	rm cdx.txt
    
    else
    
    	cat cdx.txt | sort -u > cdx1.txt && rm cdx.txt && mv cdx1.txt cdx.txt
    	total=$(wc -l < cdx.txt)
		echo -ne "${YELLOW}${BOLD}\r[✓] URLs fetched from Wayback: $CYAN${total}${NC}"

       	echo -e "${GREEN}${BOLD}\n[✓] Result is Saved to cdx.txt😎${NC}"
       	echo ""
    fi
}



otx_alienvault() {

	echo -e "${MAGENTA}${BOLD}
	┏┓┓•      ┓┏    ┓ 
	┣┫┃┓┏┓┏┓  ┃┃┏┓┓┏┃╋
	┛┗┗┗┗ ┛┗  ┗┛┗┻┗┻┗┗
	                  
	${NC}"
	echo -e "${YELLOW}${BOLD}[+] Fetching Urls from Alien Vault⏳${NC}"
	sleep 0.5

	curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=500" > alienVault.txt &
	show_spinner "${YELLOW}${BOLD} Fetching from Alien_Vault Api"


	if [[ ! -s alienVault.txt ]]; then
		echo -e "${RED}${BOLD}[!] alienVault.txt is empty😥${NC}"
		echo -e "${RED}${BOLD}[!] Removing alienVault.txt${NC}"
		rm alienVault.txt
	else
		cat alienVault.txt | sort -u | jq -r '.url_list[]?.url' > alien.txt && \
		rm alienVault.txt && mv alien.txt alienVault.txt

		total=$(wc -l < alienVault.txt)
		echo -ne "${YELLOW}${BOLD}\r[✓] URLs fetched from Alien Vault: $CYAN"${total}""
		
		echo -e "${GREEN}${BOLD}\n[✓] Result is Saved to alienVault.txt😎${NC}"
		echo ""
	fi
}


vt_data() {

	echo -e "${MAGENTA}${BOLD}
	┓┏•       ┏┳┓     ┓
	┃┃┓┏┓┓┏┏   ┃ ┏┓╋┏┓┃
	┗┛┗┛ ┗┻┛   ┻ ┗┛┗┗┻┗
	                   
${NC}"
	echo -e "${YELLOW}${BOLD}[>] Fetching urls from Virus total...⏳${NC}"
	curl -s "https://virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$apikey" > vt.txt &
	show_spinner "${YELLOW}${BOLD} Fetching from Virus_Total Api"

	if [[ ! -s "vt.txt" ]]; then
		echo -e "${RED}${BOLD}[!] vt.txt is empty😥${NC}"
		echo -e "${RED}${BOLD}[!] Removing vt.txt${NC}"
		rm vt.txt
	else
		cat vt.txt | sort -u | jq -r '.. | strings | select(test("https?://"))' | grep -E '(https?://[^\s"<>]+)' | grep "${domain}" > vt-urls.txt
		rm vt.txt && mv vt-urls.txt vt.txt

		total=$(wc -l < vt.txt)
		echo -ne "${YELLOW}${BOLD}\r[✓] URLs fetched from VirusTotal: $CYAN"${total}""

		echo -e "${GREEN}${BOLD}\n[✓] Result is Saved to vt.txt😎${NC}"
		echo ""
	fi
	
}

filter_cdx() {

	echo -e "${MAGENTA}${BOLD}
	┏┓•┓     •      ┳┳  ┓ 
	┣ ┓┃╋┏┓┏┓┓┏┓┏┓  ┃┃┏┓┃┏
	┻ ┗┗┗┗ ┛ ┗┛┗┗┫  ┗┛┛ ┗┛
	             ┛        
${NC}"

	local count=0

	#filter for juicy files
	if [[ -f "cdx.txt" && -f "alienVault.txt" && -f "vt.txt"  ]]; then


		# Filtering files
		echo -e "${YELLOW}${BOLD}[>] Filtering cdx.txt,vt.txt,alienVault.txt for intresting files...⏳${NC}"
		sleep 1
		cat cdx.txt vt.txt alienVault.txt | sort -u | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.targz|\.tgz|\.gz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.py|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc' > "juicy.txt"
		echo -e "${GREEN}${BOLD}[+] Filter Result saved to juicy.txt👌${NC}"
		sleep 0.6
		
		#Combining all urls
		echo -e "${GREEN}${BOLD}[+] Combining all urls of vt.txt alienVault.txt cdx.txt....⏳${NC}"
		cat cdx.txt vt.txt alienVault.txt | sort -u > allurls.txt && mkdir .backup && mv cdx.txt vt.txt alienVault.txt .backup/
		

		# removing gibrish files
		echo -e "${GREEN}${BOLD}[+] Filtering and removing jpeg,png,jpg from allurls.txt...⏳${NC}"
		sleep 1
		cat allurls.txt | grep -vE '\.jpg|\.png|\.jpeg|\.gif|\.woff|\.webp|\.css|\.ttf|\.svg|\.swf|\.eot|\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.targz|\.tgz|\.gz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.py|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc$' > cleanUrls.txt
		rm allurls.txt
		echo -e "${GREEN}${BOLD}[+] Done🎉${NC}"

		# total=$(wc -l < cleanUrls.txt)
    	# echo -ne "${YELLOW}${BOLD}\r[✓] Total Cleaned Urls: $CYAN"${total}""
		
		# echo -e "${GREEN}${BOLD}\n[✓] Now Clean Data are saved to cleanUrls.txt😎${NC}"
		echo ""
	else
		echo -e "${RED}${BOLD}[!] Files are empty and removed${NC}"
		exit 1
	fi

}

js_endpoints() {

	echo -e "${MAGENTA}${BOLD}
	┏┓•┓     •      ┏┳┏┓  ┏┓•┓   
	┣ ┓┃╋┏┓┏┓┓┏┓┏┓   ┃┗┓  ┣ ┓┃┏┓┏
	┻ ┗┗┗┗ ┛ ┗┛┗┗┫  ┗┛┗┛  ┻ ┗┗┗ ┛
	             ┛               
${NC}"
	local count=0
	if [[ -f "cleanUrls.txt" ]]; then

		echo -e "${GREEN}${BOLD}[>] Filtering JS files from cleanUrls.txt...⏳${NC}"
		sleep 1
		cat cleanUrls.txt | sort -u | grep "\.js$" > js.txt

		if [[ ! -s "js.txt" ]]; then
			echo -e "${RED}${BOLD}[!] No js files found in cleanurls.txt😥${NC}"
			rm js.txt

		else
			
			cat cleanUrls.txt | sort -u |grep -v "\.js$" > copy.txt
			rm cleanUrls.txt && cat copy.txt | sort -u > cleanUrls.txt && rm copy.txt

			total=$(wc -l < js.txt)
			echo -ne "${YELLOW}${BOLD}\r[✓] Total Js Files: $CYAN"${total}""

			echo -e "${GREEN}${BOLD}\n[+] Done🎉"
			echo -e "${GREEN}${BOLD}[✓] js files filtered and saved to js.txt😎${NC}"
		fi
	
	else
		echo -e "${RED}${BOLD}[!] cleanUrls.txt are empty and removed${NC}"
	fi

}

httpx_tool() {

        echo -e "${MAGENTA}${BOLD}
	┓┏      
	┣┫╋╋┏┓┓┏
	┛┗┗┗┣┛┛┗
	    ┛   
${NC}"
		
		if [[ -f "js.txt" ]]; then

			echo -e "${GREEN}${BOLD}[>] Running httpx on js files...⏳${NC}"
	        cat js.txt | httpx --status-code > js1.txt
	        echo -e "${YELLOW}${BOLD}[+] Done🎉${NC}"
	        cat js1.txt | grep "200" | cut -d "[" -f 1 > alivejs.txt
	        rm js1.txt
	        cat alivejs.txt | while read url;do curl -s $url ; done | grep -Eo '(/[a-zA-Z0-9_-]+)*)|(/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*)\.(php|aspx|asp|jsp|html|json|sql|ini|log|LOG|xml|zip|conf|htm|jspx|cgi|bak|backup)' | tr -d '"' | sort -u | cut -d ")" -f 1 > endpoints.txt
	        echo -e "${YELLOW}${BOLD}[✓] Endpoints extracted from js files are saved to endpoints.txt😎${NC}"
		
		else
			echo -e "${RED}${BOLD}[!] js.txt not found maybe empty and removed${NC}"
		fi
}

total() {


	if [[ -f js.txt && -f cleanUrls.txt ]]; then
		
		echo -e "${YELLOW}${BOLD}\r[✓] Total cleanurls.txt Files: $CYAN"$(wc -l < cleanUrls.txt)""
		echo -e "${YELLOW}${BOLD}[✓] Total js.txt Files: $CYAN"$(wc -l < js.txt)""

	elif [[ -f js.txt && ! -f cleanUrls.txt ]]; then
		echo -e "${YELLOW}${BOLD}[✓] Total js.txt Files: $CYAN"$(wc -l < js.txt)""
	elif [[ -f cleanUrls.txt && ! -f js.txt ]]; then
		echo -e "${YELLOW}${BOLD}\r[✓] Total cleanurls.txt Files: $CYAN"$(wc -l < cleanUrls.txt)""
	else
		echo -e "${RED}${BOLD}[!] Js.txt & cleanurls.txt are not found${NC}"
	fi
	
}


run_cdx
otx_alienvault
vt_data
filter_cdx
js_endpoints
total
httpx_tool
wait

