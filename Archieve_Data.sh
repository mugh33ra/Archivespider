#!/bin/bash


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
MAGENTA='\033[0;35m'
RESET="\e[0m"
CYAN='\033[0;36m'

domain=$1
apikey=845a78a30376b485ce0c66d28c41f38712bc6becf2a628a9d464d1c3c5a8f718



if [[ $# != 1 ]]; then
	echo -e "${MAGENTA}"
	cat << "EOF"
     _             _     _                  ____        _        
    / \   _ __ ___| |__ (_) _____   _____  |  _ \  __ _| |_ __ _ 
   / _ \ | '__/ __| '_ \| |/ _ \ \ / / _ \ | | | |/ _` | __/ _` |
  / ___ \| | | (__| | | | |  __/\ V /  __/ | |_| | (_| | || (_| |
 /_/   \_\_|  \___|_| |_|_|\___| \_/ \___| |____/ \__,_|\__\__,_|

					    Coded By (x)@mugh33ra

EOF
	echo ""
	echo -e "${YELLOW}Usage: $0 example.com 😒${RESET}"
	exit 1

else
	echo -e "${MAGENTA}"
	cat << "EOF"
     _             _     _                  ____        _        
    / \   _ __ ___| |__ (_) _____   _____  |  _ \  __ _| |_ __ _ 
   / _ \ | '__/ __| '_ \| |/ _ \ \ / / _ \ | | | |/ _` | __/ _` |
  / ___ \| | | (__| | | | |  __/\ V /  __/ | |_| | (_| | || (_| |
 /_/   \_\_|  \___|_| |_|_|\___| \_/ \___| |____/ \__,_|\__\__,_|

					    Coded By @mugh33ra(X)

EOF
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
        printf "\r${YELLOW}[*] $message... ${spin:$i:1}"
        sleep 0.1
    done
    printf "\r[✓] $message completed!       \n"
}





run_cdx() {

    echo -e "${MAGENTA}
	┓ ┏    ┳┓   ┓   ┳┓     
	┃┃┃┏┓┓┏┣┫┏┓┏┃┏  ┃┃┏┓╋┏┓
	┗┻┛┗┻┗┫┻┛┗┻┗┛┗  ┻┛┗┻┗┗┻
	      ┛                
${RESET}"
	local update_interval=200
	local count=0
    echo -e "${YELLOW}[+] Extracting URLs from Wayback CDX...⏳${RESET}"

    # Start curl in background and show spinner
    curl -s "https://web.archive.org/cdx/search/cdx?url=$domain/*&collapse=urlkey&output=text&fl=original" > cdx.txt &
    show_spinner "${YELLOW} Fetching from CDX Api"

    if [[ ! -s cdx.txt ]]; then
    	echo -e "${RED}[!] cdx.txt is empty😥${RESET}"
    	echo -e "${RED}[+] Removing cdx.txt...⏳${RESET}"
    	rm cdx.txt
    else
    	cat cdx.txt | sort -u > cdx1.txt && rm cdx.txt && mv cdx1.txt cdx.txt

    	while IFS= read -r line; do
    		((count++))
    		if (( count % update_interval == 0 )); then

    			echo -ne "${YELLOW}\r[✓] URLs fetched from Wayback: $CYAN${count}${RESET}"
    		fi
		done < cdx.txt

       	echo -e "${GREEN}\n[✓] Result is Saved to cdx.txt😎${RESET}"
       	echo ""
    fi
}



otx_alienvault() {

	echo -e "${MAGENTA}
	┏┓┓•      ┓┏    ┓ 
	┣┫┃┓┏┓┏┓  ┃┃┏┓┓┏┃╋
	┛┗┗┗┗ ┛┗  ┗┛┗┻┗┻┗┗
	                  
	${RESET}"
	local update_interval=200
	local count=0
	echo -e "${YELLOW}[+] Fetching Urls from Alien Vault⏳${RESET}"
	sleep 0.5

	curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=500" > alienVault.txt &
	show_spinner "${YELLOW} Fetching from Alien_Vault Api"


	if [[ ! -s alienVault.txt ]]; then
		echo -e "${RED}[!] alienVault.txt is empty😥${RESET}"
		echo -e "${RED}[!] Removing alienVault.txt${RESET}"
	else
		cat alienVault.txt | sort -u | jq -r '.url_list[]?.url' > alien.txt && \
		rm alienVault.txt && mv alien.txt alienVault.txt

		while IFS= read -r line; do
			((count++))
			if (( count % update_interval == 0 )); then
				echo -ne "${YELLOW}\r[✓] URLs fetched from Alien Vault: $CYAN"${count}""
			fi
		done < alienVault.txt
		
		echo -e "${GREEN}\n[✓] Result is Saved to alienVault.txt😎${RESET}"
		echo ""
	fi
}


vt_data() {

	echo -e "${MAGENTA}
	┓┏•       ┏┳┓     ┓
	┃┃┓┏┓┓┏┏   ┃ ┏┓╋┏┓┃
	┗┛┗┛ ┗┻┛   ┻ ┗┛┗┗┻┗
	                   
${RESET}"
	local update_interval=200
	local count=0
	echo -e "${YELLOW}[>] Fetching urls from Virus total...⏳${RESET}"
	curl -s "https://virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$apikey" > vt.txt &
	show_spinner "${YELLOW} Fetching from Virus_Total Api"

	if [[ ! -s vt.txt ]]; then
		echo -e "${RED}[!] vt.txt is empty😥${RESET}"
		echo -e "${RED}[!] Removing vt.txt${RESET}"
	else
		cat vt.txt | sort -u | jq -r '.. | strings | select(test("https?://"))' | grep -E '(https?://[^\s"<>]+)' | grep "${domain}" > vt-urls.txt
		rm vt.txt && mv vt-urls.txt vt.txt

		while IFS= read -r line; do
			((count++))
			if (( count % update_interval == 0 )); then
				echo -ne "${YELLOW}\r[✓] URLs fetched from VirusTotal: $CYAN"${count}""
			fi
		done < vt.txt

		echo -e "${GREEN}\n[✓] Result is Saved to vt.txt😎${RESET}"
		echo ""
	fi
	
}

filter_cdx() {

	echo -e "${MAGENTA}
	┏┓•┓     •      ┳┳  ┓ 
	┣ ┓┃╋┏┓┏┓┓┏┓┏┓  ┃┃┏┓┃┏
	┻ ┗┗┗┗ ┛ ┗┛┗┗┫  ┗┛┛ ┗┛
	             ┛        
${RESET}"

	local update_interval=200
	local count=0
	echo -e "${YELLOW}[>] Filtering cdx.txt,vt.txt,alienVault.txt for intresting files...⏳${RESET}"
	sleep 1

	#filter for juicy files
	cat cdx.txt vt.txt alienVault.txt | sort -u | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.targz|\.tgz|\.gz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.py|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc' > "juicy.txt"
	
	echo -e "${GREEN}[+] Done🎉${RESET}"
	echo -e "${GREEN}[+] Filter Result saved to juicy.txt👌${RESET}"
	sleep 0.6
	
	echo -e "${GREEN}[+] Combining all urls of vt.txt alienVault.txt cdx.txt....⏳${RESET}"
	cat cdx.txt vt.txt alienVault.txt | sort -u > allurls.txt && mkdir .backup && mv cdx.txt vt.txt alienVault.txt .backup/
	
	echo -e "${GREEN}[+] Filtering and removing jpeg,png,jpg from allurls.txt...⏳${RESET}"
	sleep 1
	cat allurls.txt | grep -vE '\.jpg|\.png|\.jpeg|\.gif|\.woff|\.webp|\.css|\.ttf|\.svg|\.swf|\.eot|\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.targz|\.tgz|\.gz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.py|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc$' > cleanUrls.txt
	rm allurls.txt


    while IFS= read -r line; do
    	((count++))
    	echo -ne "${YELLOW}\r[✓] Total Cleaned Urls: $CYAN"${count}""
    done < cleanUrls.txt
	
	echo -e "${GREEN}\n[✓] Now Clean Data are saved to cleanUrls.txt😎${RESET}"
	echo ""
}

js_endpoints() {

	echo -e "${GREEN}
	┏┓•┓     •      ┏┳┏┓  ┏┓•┓   
	┣ ┓┃╋┏┓┏┓┓┏┓┏┓   ┃┗┓  ┣ ┓┃┏┓┏
	┻ ┗┗┗┗ ┛ ┗┛┗┗┫  ┗┛┗┛  ┻ ┗┗┗ ┛
	             ┛               
${RESET}"
	local update_interval=200
	local count=0
	echo -e "${GREEN}[>] Filtering JS files from allurls.txt...⏳${RESET}"
	sleep 1
	cat cleanUrls.txt | sort -u | grep "\.js$" > js.txt
	cat cleanUrls.txt | sort -u |grep -v "\.js$" > copy.txt
	rm cleanUrls.txt && cat copy.txt | uro > cleanUrls.txt && rm copy.txt

    while IFS= read -r line; do
    	((count++))
    	echo -ne "${YELLOW}\r[✓] Total Js Files: $CYAN"${count}""
    done < js.txt
	echo -e "${GREEN}\n[+] Done🎉"
	echo -e "${GREEN}\n[✓] js files filtered and saved to js.txt😎${RESET}"

}

httpx_tool() {

        echo -e "${GREEN}
	┓┏      
	┣┫╋╋┏┓┓┏
	┛┗┗┗┣┛┛┗
	    ┛   
${RESET}"
        echo -e "${GREEN}[>] Running httpx on js files...⏳${RESET}"
        cat js.txt | httpx --status-code > js1.txt
        echo -e "${YELLOW}[+] Done🎉${RESET}"
        cat js1.txt | grep "200" | cut -d "[" -f 1 > alivejs.txt
        rm js1.txt
        cat alivejs.txt | while read url;do curl -s $url ; done | grep -Eo '(/[a-zA-Z0-9_-]+)*)|(/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*)\.(php|aspx|asp|jsp|html|json|sql|ini|log|LOG|xml|zip|conf|htm|jspx|cgi|bak|backup)' | tr -d '"' | sort -u | cut -d ")" -f 1 > endpoints.txt
        echo -e "${YELLOW}[✓] Endpoints extracted from js files are saved to endpoints.txt😎${RESET}"

}
run_cdx
otx_alienvault
vt_data
filter_cdx
js_endpoints
httpx_tool
wait

