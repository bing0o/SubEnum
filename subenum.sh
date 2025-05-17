#!/bin/bash
#
# script for subdomain enumeration using the best tools and online services:
#   * findomain: https://github.com/Edu4rdSHL/findomain
#   * SubFinder: https://github.com/projectdiscovery/subfinder
#   * Amass: https://github.com/OWASP/Amass
#   * AssetFinder: https://github.com/tomnomnom/assetfinder
#   * DNSx: https://github.com/projectdiscovery/dnsx
#   * PureDNS: https://github.com/d3mondev/puredns
#

bold="\e[1m"
Underlined="\e[4m"
red="\e[31m"
green="\e[32m"
blue="\e[34m"
yellow="\e[33m"
magenta="\e[35m"
cyan="\e[36m"
end="\e[0m"
VERSION="2025-05-17"

PRG=${0##*/}

# Configuration file path
CONFIG_FILE="$HOME/.config/subenum/config.conf"

# Create config directory and file if it doesn't exist
if [ ! -d "$HOME/.config/subenum" ]; then
    mkdir -p "$HOME/.config/subenum"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOL
# SubEnum Configuration File
# API Keys for various services

# SecurityTrails API Key
SECURITYTRAILS_API_KEY=""

# GitHub API Token
GITHUB_TOKEN=""

# VirusTotal API Key
VT_API_KEY=""

# Chaos API Key
CHAOS_API_KEY=""

# Default wordlist for bruteforce
WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# Default thread count
THREAD_COUNT="40"

# Default timeout (seconds)
TIMEOUT="10"
EOL
    echo -e "${blue}[*] Created config file at $CONFIG_FILE${end}"
    echo -e "${blue}[*] Please edit this file to add your API keys${end}"
fi

# Load configuration
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

Usage(){
	while read -r line; do
		printf "%b\n" "$line"
	done <<-EOF
	\r
	\r# ${bold}${blue}Options${end}:
	\r    -d, --domain       - Domain to enumerate
	\r    -l, --list         - List of domains (file path)
	\r    -u, --use          - Tools to be used ex(Findomain,Subfinder,...,etc)
	\r    -e, --exclude      - Tools to be excluded ex(Findomain,Amass,...,etc)
	\r    -o, --output       - The output file path (Default: <TargetDomain>-DATE-TIME.txt)
	\r    -s, --silent       - Silent mode - only outputs found subdomains (Results: subenum-<DOMAIN>.txt)
	\r    -k, --keep         - Keep temporary files (results from each tool)
	\r    -r, --resolve      - Probe for working HTTP/HTTPS subdomains (Output: resolved-<DOMAIN>.txt)
	\r    -t, --thread       - Thread count for DNS resolution (Default: 40)
	\r    -p, --parallel     - Use parallel processing for faster results (Not compatible with -e/-u)
	\r    -f, --format       - Output format: txt,csv,json (Default: txt)
	\r    -w, --wordlist     - Custom wordlist for bruteforce methods
	\r    -a, --analytics    - Show analytics and statistics at the end
	\r    --takeover         - Check for potential subdomain takeover vulnerabilities
	\r    --config           - Path to custom config file
	\r    --update-config    - Update API keys in config file
	\r    -h, --help         - Display this help message and exit
	\r    -v, --version      - Display the version and exit

	\r# ${bold}${blue}Available Tools${end}:
	\r	  ${cyan}Passive Enumeration${end}: wayback,crt,abuseipdb,hackertarget,rapiddns,riddler,securitytrails,
	\r	      sublist3r,certspotter,github,alienvault,threatcrowd,virustotal
	\r	  ${cyan}Active Tools${end}: Findomain,Subfinder,Amass,Assetfinder,gobuster,dnsgen,chaos,dnssearch,shuffledns
	\r	  ${cyan}Validation Tools${end}: dnsx,puredns,httpx

	\r# ${bold}${blue}Examples${end}:
	\r    - To use specific tools:
	\r       $PRG -d hackerone.com -u Findomain,wayback,Subfinder
	\r    - To exclude specific tools:
	\r       $PRG -d hackerone.com -e Amass,Assetfinder
	\r    - To use all tools with parallel processing:
	\r       $PRG -d hackerone.com --parallel
	\r    - To scan multiple domains:
	\r       $PRG -l domains.txt
	\r    - To scan and check for subdomain takeover:
	\r       $PRG -d target.com --takeover
	\r    - To output in JSON format with analytics:
	\r       $PRG -d target.com -f json -a
EOF
	exit 1
}


spinner(){
	processing="${1}"
	while true; 
	do
		dots=(
			"/"
			"-"
			"\\"
			"|"
			)
		for dot in ${dots[@]};
		do
			printf "[${dot}] ${processing} \U1F50E"
			printf "                                    \r"
			sleep 0.3
		done
		
	done
}


wayback() {
	[ "$silent" == True ] && curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u | anew subenum-$domain.txt  || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}WayBackMachine${end}" &
			PID="$!"
		}
		curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > tmp-wayback-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] WayBackMachine$end: $(wc -l < tmp-wayback-$domain)"
	}
}

crt() {
	[ "$silent" == True ] && curl -sk "https://crt.sh/?q=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}crt.sh${end}" &
			PID="$!"
		}
		curl -sk "https://crt.sh/?q=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > tmp-crt-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] crt.sh$end: $(wc -l < tmp-crt-$domain)" 
	}
}

abuseipdb() {
	[ "$silent" == True ] && curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: firefox" -b "abuseipdb_session=" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}abuseipdb.sh${end}" &
			PID="$!"
		}
		curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: firefox" -b "abuseipdb_session=" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" | sort -u > tmp-abuseipdb-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] abuseipdb$end: $(wc -l < tmp-abuseipdb-$domain)" 
	}
}

Findomain() {
	[ "$silent" == True ] && findomain -t $domain -q 2>/dev/null | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Findomain${end}" &
			PID="$!"
		}
		findomain -t $domain -u tmp-findomain-$domain &>/dev/null
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Findomain$end: $(wc -l tmp-findomain-$domain 2>/dev/null | awk '{print $1}')"
	}
}

Subfinder() {
	[ "$silent" == True ] && subfinder -all -silent -d $domain 2>/dev/null | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}SubFinder${end}" &
			PID="$!"
		}
		subfinder -all -silent -d $domain 1> tmp-subfinder-$domain 2>/dev/null
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] SubFinder$end: $(wc -l < tmp-subfinder-$domain)"
	}
}

Amass() {
	# amass is with "-passive" option to make it faster, but it may cuz less results
	[ "$silent" == True ] && amass enum -passive -norecursive -noalts -d $domain 2>/dev/null | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Amass${end}" &
			PID="$!"
		}
		amass enum -passive -norecursive -noalts -d $domain 1> tmp-amass-$domain 2>/dev/null
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Amass$end: $(wc -l < tmp-amass-$domain)"
	}
}

Assetfinder() {
	[ "$silent" == True ] && assetfinder --subs-only $domain | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}AssetFinder${end}" &
			PID="$!"
		}
		assetfinder --subs-only $domain > tmp-assetfinder-$domain
		kill ${PID} 2>/dev/null
		echo -e "$bold[*] AssetFinder$end: $(wc -l < tmp-assetfinder-$domain)"
	}
}

# New subdomain enumeration functions

hackertarget() {
	[ "$silent" == True ] && curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -v "API count exceeded" | grep "$domain" | cut -d "," -f1 | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}HackerTarget${end}" &
			PID="$!"
		}
		curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -v "API count exceeded" | grep "$domain" | cut -d "," -f1 > tmp-hackertarget-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] HackerTarget$end: $(wc -l < tmp-hackertarget-$domain)"
	}
}

rapiddns() {
	[ "$silent" == True ] && curl -s "https://rapiddns.io/subdomain/$domain?full=1" | grep -oP "<td>\K[^<]*\.$domain" | sed 's/\.$domain//g' | grep -v "\*" | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}RapidDNS${end}" &
			PID="$!"
		}
		curl -s "https://rapiddns.io/subdomain/$domain?full=1" | grep -oP "<td>\K[^<]*\.$domain" | sed 's/\.$domain//g' | grep -v "\*" > tmp-rapiddns-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] RapidDNS$end: $(wc -l < tmp-rapiddns-$domain)"
	}
}

riddler() {
	[ "$silent" == True ] && curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([a-zA-Z][a-zA-Z0-9_-]*)\.)+$domain" | sort -u | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Riddler${end}" &
			PID="$!"
		}
		curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([a-zA-Z][a-zA-Z0-9_-]*)\.)+$domain" | sort -u > tmp-riddler-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Riddler$end: $(wc -l < tmp-riddler-$domain)"
	}
}

securitytrails() {
	# This requires an API key to be set as SECURITYTRAILS_API_KEY in your environment
	if [ -z "$SECURITYTRAILS_API_KEY" ]; then
		echo -e "$red[!] SECURITYTRAILS_API_KEY not set. Skipping SecurityTrails.${end}"
		return
	fi
	[ "$silent" == True ] && curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/$domain/subdomains?children_only=false" | jq -r '.subdomains[]' | sed -e "s/$/.$domain/" | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}SecurityTrails${end}" &
			PID="$!"
		}
		curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/$domain/subdomains?children_only=false" | jq -r '.subdomains[]' | sed -e "s/$/.$domain/" > tmp-securitytrails-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] SecurityTrails$end: $(wc -l < tmp-securitytrails-$domain)"
	}
}

sublist3r() {
	# Check if sublist3r is installed
	if ! command -v sublist3r &> /dev/null; then
		echo -e "$red[!] Sublist3r not found. Please install it from https://github.com/aboul3la/Sublist3r${end}"
		return
	fi

	[ "$silent" == True ] && sublist3r -d $domain -o tmp-sublist3r-$domain 2>/dev/null && cat tmp-sublist3r-$domain | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Sublist3r${end}" &
			PID="$!"
		}
		sublist3r -d $domain -o tmp-sublist3r-$domain 2>/dev/null
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Sublist3r$end: $(wc -l < tmp-sublist3r-$domain)"
	}
}

certspotter() {
	[ "$silent" == True ] && curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | grep "$domain" | sort -u | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}CertSpotter${end}" &
			PID="$!"
		}
		curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | grep "$domain" | sort -u > tmp-certspotter-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] CertSpotter$end: $(wc -l < tmp-certspotter-$domain)"
	}
}

github() {
	# This requires a GitHub token to be set as GITHUB_TOKEN in your environment for better rate limits
	github_header=""
	if [ ! -z "$GITHUB_TOKEN" ]; then
		github_header="-H 'Authorization: token $GITHUB_TOKEN'"
	fi

	[ "$silent" == True ] && curl -s $github_header "https://api.github.com/search/code?q=$domain&per_page=100" | jq -r '.items[].html_url' | sort -u | grep -o "https://[^/]*\.$domain" | cut -d'/' -f3 | sort -u | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}GitHub${end}" &
			PID="$!"
		}
		curl -s $github_header "https://api.github.com/search/code?q=$domain&per_page=100" | jq -r '.items[].html_url' | sort -u | grep -o "https://[^/]*\.$domain" | cut -d'/' -f3 | sort -u > tmp-github-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] GitHub$end: $(wc -l < tmp-github-$domain)"
	}
}

alienvault() {
	[ "$silent" == True ] && curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r '.passive_dns[].hostname' | grep "$domain" | sort -u | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}AlienVault${end}" &
			PID="$!"
		}
		curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r '.passive_dns[].hostname' | grep "$domain" | sort -u > tmp-alienvault-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] AlienVault$end: $(wc -l < tmp-alienvault-$domain)"
	}
}

threatcrowd() {
	[ "$silent" == True ] && curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r '.subdomains[]' | sort -u | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}ThreatCrowd${end}" &
			PID="$!"
		}
		curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r '.subdomains[]' | sort -u > tmp-threatcrowd-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] ThreatCrowd$end: $(wc -l < tmp-threatcrowd-$domain)"
	}
}

virustotal() {
	# This requires a VirusTotal API key to be set as VT_API_KEY in your environment
	if [ -z "$VT_API_KEY" ]; then
		echo -e "$red[!] VT_API_KEY not set. Skipping VirusTotal.${end}"
		return
	fi
	[ "$silent" == True ] && curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$domain/subdomains?limit=40" | jq -r '.data[].id' | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}VirusTotal${end}" &
			PID="$!"
		}
		curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$domain/subdomains?limit=40" | jq -r '.data[].id' > tmp-virustotal-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] VirusTotal$end: $(wc -l < tmp-virustotal-$domain)"
	}
}

gobuster() {
	# Check if gobuster is installed
	if ! command -v gobuster &> /dev/null; then
		echo -e "$red[!] Gobuster not found. Please install it from https://github.com/OJ/gobuster${end}"
		return
	fi

	# Check if wordlist exists
	wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
	if [ ! -f "$wordlist" ]; then
		echo -e "$red[!] Wordlist not found at $wordlist. Using a default small wordlist.${end}"
		wordlist="/usr/share/wordlists/dirb/common.txt"
		if [ ! -f "$wordlist" ]; then
			echo -e "$red[!] No suitable wordlist found. Skipping Gobuster.${end}"
			return
		fi
	fi

	[ "$silent" == True ] && gobuster dns -d $domain -w $wordlist -q 2>/dev/null | cut -d' ' -f2 | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Gobuster${end}" &
			PID="$!"
		}
		gobuster dns -d $domain -w $wordlist -q 2>/dev/null | cut -d' ' -f2 > tmp-gobuster-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Gobuster$end: $(wc -l < tmp-gobuster-$domain)"
	}
}

dnsgen() {
	# Check if dnsgen is installed
	if ! command -v dnsgen &> /dev/null; then
		echo -e "$red[!] Dnsgen not found. Please install it from https://github.com/ProjectAnte/dnsgen${end}"
		return
	fi

	# Create a temporary file with the current known subdomains
	cat tmp-* > tmp-combined-$domain 2>/dev/null

	[ "$silent" == True ] && cat tmp-combined-$domain | dnsgen - | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}DNSGen${end}" &
			PID="$!"
		}
		cat tmp-combined-$domain | dnsgen - > tmp-dnsgen-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] DNSGen$end: $(wc -l < tmp-dnsgen-$domain)"
	}
}

chaos() {
	# This requires a Chaos API key to be set as CHAOS_API_KEY in your environment
	if [ -z "$CHAOS_API_KEY" ]; then
		echo -e "$red[!] CHAOS_API_KEY not set. Skipping Chaos.${end}"
		return
	fi
	[ "$silent" == True ] && curl -s -H "Authorization: $CHAOS_API_KEY" "https://dns.projectdiscovery.io/dns/$domain/subdomains" | jq -r '.subdomains[]' | sed -e "s/$/.$domain/" | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Chaos${end}" &
			PID="$!"
		}
		curl -s -H "Authorization: $CHAOS_API_KEY" "https://dns.projectdiscovery.io/dns/$domain/subdomains" | jq -r '.subdomains[]' | sed -e "s/$/.$domain/" > tmp-chaos-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Chaos$end: $(wc -l < tmp-chaos-$domain)"
	}
}


USE() {
	for i in $lu; do
		$i
	done
	[[ $out != False ]] && OUT $out || OUT
}


EXCLUDE() {
	for i in ${list[@]}; do
		if [[ " ${le[@]} " =~ " ${i} " ]]; then
			continue
		else
			$i
		fi
	done
	[[ $out != False ]] && OUT $out || OUT
}

OUT(){
	[ "$silent" == False ] && { 
		[ -n "$1" ] && output="$1" || output="$domain-$(date +'%Y-%m-%d').txt"
		result=$(sort -u tmp-* | wc -l)
		
		# Handle different output formats
		if [ -n "$format" ]; then
			output_formats
		else
			sort -u tmp-* > $output
			echo -e $green"[+] The Final Results:$end ${result}"
		fi
		
		# If analytics is enabled, show detailed statistics
		[ "$analytics" == True ] && analyze_results
		
		# Check for DNS resolution if requested
		[ $resolve == True ] && ALIVE "$output" "$domain"
		
		# Check for subdomain takeover vulnerabilities if requested
		[ "$takeover" == True ] && check_takeover

		# Clean up temporary files unless keep flag is set
		[ $delete == True ] && rm tmp-*	
	}
}


ALIVE(){
	[ "$silent" == False ] && printf "$bold[+] Resolving $end"
	printf "                        \r"
	
	# First use dnsx for basic resolution
	cat $1 | dnsx -silent -threads $thread > "dns-resolved-$2.txt"
	
	# Then use httprobe or httpx for HTTP/HTTPS validation if available
	if command -v httprobe &> /dev/null; then
		# Preferred: Use httprobe if available
		cat "dns-resolved-$2.txt" | httprobe -c $thread > "resolved-$2.txt"
		
		# Create additional files for HTTP and HTTPS hosts if not in silent mode
		if [ "$silent" == False ]; then
			cat "resolved-$2.txt" | grep "http://" > "http-$2.txt"
			cat "resolved-$2.txt" | grep "https://" > "https-$2.txt"
			echo -e $green"[+] HTTP hosts:$end $(wc -l < http-$2.txt)"
			echo -e $green"[+] HTTPS hosts:$end $(wc -l < https-$2.txt)"
		fi
		echo -e $green"[+] Web probing with Httprobe completed.${end}"
	elif command -v httpx &> /dev/null; then
		# Alternative: Use httpx if httprobe is not available
		cat "dns-resolved-$2.txt" | httpx -silent -threads $thread -o "resolved-$2.txt"
		
		# Create additional files for HTTP and HTTPS hosts if not in silent mode
		if [ "$silent" == False ]; then
			cat "resolved-$2.txt" | grep "http://" > "http-$2.txt"
			cat "resolved-$2.txt" | grep "https://" > "https-$2.txt"
			echo -e $green"[+] HTTP hosts:$end $(wc -l < http-$2.txt)"
			echo -e $green"[+] HTTPS hosts:$end $(wc -l < https-$2.txt)"
		fi
		echo -e $green"[+] Web probing with HTTPx completed.${end}"
	else
		# Fallback if neither httprobe nor httpx are available
		cp "dns-resolved-$2.txt" "resolved-$2.txt"
		echo -e $yellow"[!] Neither httprobe nor httpx are installed. Only DNS resolution performed.${end}"
	fi
	
	[ "$silent" == False ] && echo -e $green"[+] Resolved:$end $(wc -l < resolved-$2.txt)"
}


LIST() {
	lines=$(wc -l < $hosts)
	count=1
	while read domain; do
		[ "$silent" == False ] && echo -e "\n${Underlined}${bold}${green}[+] Domain ($count/$lines):${end} ${domain}"
		[ $prv == "a" ] && {
			[[ ${PARALLEL} == True ]] && {
				spinner "Reconnaissance" &
				PID="$!"
				export -f wayback crt abuseipdb Findomain Subfinder Amass Assetfinder spinner
				export domain silent bold end
				parallel -j7 ::: wayback crt abuseipdb Findomain Subfinder Amass Assetfinder
				kill ${PID}
				[[ $out != False ]] && OUT $out || OUT
			} || {
				wayback
				crt
				abuseipdb
				Findomain 
				Subfinder 
				Amass 
				Assetfinder
				[[ $out != False ]] && OUT $out || OUT
			}
		}
		[ $prv == "e" ] && EXCLUDE 
		[ $prv == "u" ] && USE 
		let count+=1
	done < $hosts
}

Main() {
	[ $domain == False ] && [ $hosts == False ] && { echo -e $red"[-] Argument -d/--domain OR -l/--list is Required!"$end; Usage; }
	[ $use != False ] && [ $exclude != False ] && { echo -e $Underlined$red"[!] You can use only one Option: -e/--exclude OR -u/--use"$end; Usage; }

	[ $domain != False ] && { 
		# Set default output filename if not specified
		[ "$out" == False ] && out="$domain-$(date +'%Y-%m-%d').txt"
		
		[ $use == False ] && [ $exclude == False ] && { 
			[[ ${PARALLEL} == True ]] && {
				spinner "Reconnaissance" &
				PID="$!"
				export -f wayback crt abuseipdb hackertarget rapiddns Findomain Subfinder Amass Assetfinder spinner
				export domain silent bold end
				parallel -j10 ::: wayback crt abuseipdb hackertarget rapiddns Findomain Subfinder Amass Assetfinder
				
				# Run additional tools after the first batch
				[ "$silent" == False ] && echo -e "${blue}[*] Running additional enumeration techniques...${end}"
				export -f dnssearch shuffledns puredns
				parallel -j3 ::: dnssearch shuffledns puredns
				
				kill ${PID} 2>/dev/null
			} || {
				# Run core enumeration tools
				wayback
				crt
				abuseipdb
				hackertarget
				rapiddns
				Findomain 
				Subfinder
				Amass 
				Assetfinder
				
				# Run additional tools if not in silent mode
				[ "$silent" == False ] && {
					echo -e "${blue}[*] Running additional enumeration techniques...${end}"
					dnssearch
					shuffledns
					puredns
				}
			}
			[ "$out" == False ] && OUT || OUT $out
		} || { 
			[ $use != False ] && USE 
			[ $exclude != False ] && EXCLUDE
		}
	}
	[ "$hosts" != False ] && { 
		[ $use != False ] && prv=u
		[ $exclude != False ] && prv=e
		[ $use == False ] && [ $exclude == False ] && prv=a
		LIST
	}
	
	# Display end time and duration
	[ "$silent" == False ] && {
		end_time=$(date +%s)
		duration=$((end_time - start_time))
		echo -e "\n${blue}[*] Finished at: $(date +"%Y-%m-%d %H:%M:%S")${end}"
		echo -e "${blue}[*] Total runtime: $(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))${end}"
	}
}


domain=False
hosts=False
use=False
exclude=False
silent=False
delete=True
out=False
resolve=False
thread=40
PARALLEL=False

list=(
	wayback
	crt
	abuseipdb
	hackertarget
	rapiddns
	riddler
	securitytrails
	sublist3r
	certspotter
	github
	alienvault
	threatcrowd
	virustotal
	Findomain
	Subfinder
	Amass
	Assetfinder
	gobuster
	dnsgen
	chaos
	shuffledns
	dnssearch
	puredns
	)

# New enhanced subdomain discovery functions

# ShuffleDNS subdomain bruteforce function
shuffledns() {
	# Check if shuffledns is installed
	if ! command -v shuffledns &> /dev/null; then
		echo -e "$red[!] shuffledns not found. Please install it from https://github.com/projectdiscovery/shuffledns${end}"
		return
	 fi

	# Wordlist check
	if [ -z "$custom_wordlist" ]; then
		wordlist="$WORDLIST"
		if [ ! -f "$wordlist" ]; then
			echo -e "$yellow[!] Default wordlist not found. Using a smaller built-in list.${end}"
			wordlist="/usr/share/wordlists/dirb/common.txt"
			if [ ! -f "$wordlist" ]; then
				echo -e "$red[!] No suitable wordlist found. Skipping ShuffleDNS.${end}"
				return
			fi
		fi
	else
		wordlist="$custom_wordlist"
		if [ ! -f "$wordlist" ]; then
			echo -e "$red[!] Custom wordlist not found: $wordlist. Skipping ShuffleDNS.${end}"
			return
		fi
	fi

	# Resolvers check
	resolvers="/tmp/resolvers.txt"
	if [ ! -f "$resolvers" ]; then
		echo -e "$blue[*] Downloading resolvers...${end}"
		curl -s https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt > "$resolvers"
	fi

	[ "$silent" == True ] && {
		shuffledns -d "$domain" -w "$wordlist" -r "$resolvers" -silent 2>/dev/null | anew subenum-$domain.txt
	} || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}ShuffleDNS${end}" &
			PID="$!"
		}
		shuffledns -d "$domain" -w "$wordlist" -r "$resolvers" -silent 2>/dev/null > tmp-shuffledns-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] ShuffleDNS$end: $(wc -l < tmp-shuffledns-$domain)"
	}
}

# PureDNS improved resolution function
puredns() {
	# Check if puredns is installed
	if ! command -v puredns &> /dev/null; then
		echo -e "$red[!] puredns not found. Please install it from https://github.com/d3mondev/puredns${end}"
		return
	fi

	# Resolvers check
	resolvers="/tmp/resolvers.txt"
	if [ ! -f "$resolvers" ]; then
		echo -e "$blue[*] Downloading resolvers...${end}"
		curl -s https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt > "$resolvers"
	fi

	# Create a temporary file with all found subdomains
	cat tmp-* > tmp-combined-$domain 2>/dev/null

	[ "$silent" == True ] && {
		puredns resolve tmp-combined-$domain -r "$resolvers" --quiet 2>/dev/null | anew subenum-$domain.txt
	} || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}PureDNS${end}" &
			PID="$!"
		}
		puredns resolve tmp-combined-$domain -r "$resolvers" --quiet 2>/dev/null > tmp-puredns-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] PureDNS$end: $(wc -l < tmp-puredns-$domain)"
	}
}

# Nuclei subdomain takeover check function
check_takeover() {
	if ! command -v nuclei &> /dev/null; then
		echo -e "$red[!] nuclei not found. Please install it from https://github.com/projectdiscovery/nuclei${end}"
		return
	fi

	if [ ! -f "resolved-$domain.txt" ]; then
		echo -e "$yellow[!] No resolved domains found. Running resolver first...${end}"
		ALIVE "$output" "$domain"
	fi

	echo -e "$blue[*] Checking for subdomain takeover vulnerabilities...${end}"
	nuclei -l "resolved-$domain.txt" -t takeovers/ -silent -c 50 > "takeover-$domain.txt"
	takeover_count=$(wc -l < "takeover-$domain.txt")

	if [ "$takeover_count" -gt 0 ]; then
		echo -e "$red[!] Found $takeover_count potential subdomain takeover vulnerabilities!${end}"
		echo -e "$yellow[*] Results saved to takeover-$domain.txt${end}"
	else
		echo -e "$green[+] No subdomain takeover vulnerabilities found.${end}"
		rm "takeover-$domain.txt" 2>/dev/null
	fi
}

# DNSSearch function for advanced permutation scanning
dnssearch() {
	if ! command -v dnsx &> /dev/null; then
		echo -e "$red[!] dnsx not found. Please install it for DNS validation${end}"
		return
	fi

	# Create permutations based on known subdomains
	cat tmp-* > tmp-combined-$domain 2>/dev/null

	# Common prefixes and suffixes for permutations
	prefixes=("dev" "stage" "test" "admin" "api" "stg" "beta" "alpha" "prod" "demo" "lab" "qa")
	suffixes=("-dev" "-staging" "-test" "-prod" "-demo" "-web" "-api" "-admin")

	# Generate permutations based on discovered subdomains
	echo -e "$blue[*] Generating subdomain permutations...${end}"
	cat tmp-combined-$domain | while read sub; do
		base=$(echo "$sub" | cut -d. -f1)
		for prefix in "${prefixes[@]}"; do
			echo "$prefix-$base.$domain"
		done
		for suffix in "${suffixes[@]}"; do
			echo "$base$suffix.$domain"
		done
	done > tmp-permutations-$domain

	# Validate the permutations
	echo -e "$blue[*] Validating permutations...${end}"
	cat tmp-permutations-$domain | dnsx -silent -a -resp -o tmp-dnssearch-$domain
	
	[ "$silent" == True ] && {
		cat tmp-dnssearch-$domain | cut -d' ' -f1 | anew subenum-$domain.txt
	} || {
		echo -e "$bold[*] DNSSearch$end: $(wc -l < tmp-dnssearch-$domain)"
	}
}

# Function to output results in different formats
output_formats() {
	local output_base="${output%.*}"

	case "$format" in
		json)
			echo "{\"domain\":\"$domain\",\"subdomains\":[" > "${output_base}.json"
			sort -u tmp-* | sed 's/^/"/;s/$/",/' | sed '$ s/,$//' >> "${output_base}.json"
			echo "]}" >> "${output_base}.json"
			echo -e "${green}[+] JSON output saved to ${output_base}.json${end}"
			;;
		csv)
			echo "subdomain" > "${output_base}.csv"
			sort -u tmp-* >> "${output_base}.csv"
			echo -e "${green}[+] CSV output saved to ${output_base}.csv${end}"
			;;
		txt|*)
			sort -u tmp-* > "$output"
			echo -e "${green}[+] TXT output saved to ${output}${end}"
			;;
	esac
}

# Function to analyze results and show statistics
analyze_results() {
	echo -e "\n${bold}${blue}[*] Results Analysis${end}"
	total=$(sort -u tmp-* | wc -l)
	echo -e "${blue}[*] Total unique subdomains: $total${end}"
	
	# Most common patterns
	echo -e "${blue}[*] Most common subdomain patterns:${end}"
	sort -u tmp-* | cut -d. -f1 | sort | uniq -c | sort -nr | head -5 | while read count pattern; do
		echo -e "    - $pattern: $count occurrences"
	done
	
	# Show contribution from each source
	echo -e "\n${blue}[*] Contribution from each source:${end}"
	for source in tmp-*; do
		if [ -f "$source" ]; then
			file_name=$(echo "$source" | sed "s/tmp-//g" | sed "s/-$domain//g")
			count=$(wc -l < "$source")
			perc=$(echo "scale=2; ($count / $total) * 100" | bc)
			echo -e "    - $file_name: $count ($perc%)"
		fi
	done
	
	# Unique contributions
	echo -e "\n${blue}[*] Unique contributions from each source:${end}"
	for source in tmp-*; do
		if [ -f "$source" ]; then
			file_name=$(echo "$source" | sed "s/tmp-//g" | sed "s/-$domain//g")
			other_sources=$(find . -name "tmp-*" ! -name "$source" -type f -exec cat {} \; 2>/dev/null | sort -u)
			unique_count=$(grep -vFf <(echo "$other_sources") "$source" | wc -l)
			if [ "$unique_count" -gt 0 ]; then
				echo -e "    - $file_name: $unique_count unique subdomains"
			fi
		fi
	done
}

# Function to update configuration file
update_config() {
	echo -e "${blue}[*] Updating configuration file${end}"
	echo -e "${yellow}Enter new values (leave empty to keep current value)${end}"
	
	# Load current values
	source "$CONFIG_FILE"
	
	# Ask for new values
	read -p "SecurityTrails API Key [$SECURITYTRAILS_API_KEY]: " new_securitytrails
	read -p "GitHub Token [$GITHUB_TOKEN]: " new_github
	read -p "VirusTotal API Key [$VT_API_KEY]: " new_vt
	read -p "Chaos API Key [$CHAOS_API_KEY]: " new_chaos
	read -p "Default Wordlist [$WORDLIST]: " new_wordlist
	read -p "Default Thread Count [$THREAD_COUNT]: " new_thread
	
	# Update only non-empty values
	[ -n "$new_securitytrails" ] && sed -i "s/SECURITYTRAILS_API_KEY=.*/SECURITYTRAILS_API_KEY=\"$new_securitytrails\"/" "$CONFIG_FILE"
	[ -n "$new_github" ] && sed -i "s/GITHUB_TOKEN=.*/GITHUB_TOKEN=\"$new_github\"/" "$CONFIG_FILE"
	[ -n "$new_vt" ] && sed -i "s/VT_API_KEY=.*/VT_API_KEY=\"$new_vt\"/" "$CONFIG_FILE"
	[ -n "$new_chaos" ] && sed -i "s/CHAOS_API_KEY=.*/CHAOS_API_KEY=\"$new_chaos\"/" "$CONFIG_FILE"
	[ -n "$new_wordlist" ] && sed -i "s|WORDLIST=.*|WORDLIST=\"$new_wordlist\"|" "$CONFIG_FILE"
	[ -n "$new_thread" ] && sed -i "s/THREAD_COUNT=.*/THREAD_COUNT=\"$new_thread\"/" "$CONFIG_FILE"
	
	echo -e "${green}[+] Configuration updated successfully!${end}"
	# Reload configuration
	source "$CONFIG_FILE"
}


while [ -n "$1" ]; do
	case $1 in
		-d|--domain)
			domain=$2
			shift ;;
		-l|--list)
			hosts=$2
			shift ;;
		-u|--use)
			use=$2
			lu=${use//,/ }
			for i in $lu; do
				if [[ ! " ${list[@]} " =~ " ${i} " ]]; then
					echo -e $red$Underlined"[-] Unknown Function: $i"$end
					Usage
				fi
			done
			shift ;;
		-e|--exclude)
			exclude=$2
			le=${exclude//,/ }
			for i in $le; do
				if [[ ! " ${list[@]} " =~ " ${i} " ]]; then
					echo -e $red$Underlined"[-] Unknown Function: $i"$end
					Usage
				fi
			done
			shift ;;
		-o|--output)
			out=$2
			shift ;;
		-s|--silent)
			silent=True ;;
		-k|--keep)
			delete=False ;;
		-r|--resolve)
			resolve=True ;;
		-t|--thread)
			thread=$2
			shift ;;
		-f|--format)
			format=$2
			shift ;;
		-w|--wordlist)
			custom_wordlist=$2
			shift ;;
		-a|--analytics)
			analytics=True ;;
		--takeover)
			takeover=True ;;
		--config)
			config_file=$2
			if [ -f "$config_file" ]; then
				CONFIG_FILE="$config_file"
				source "$CONFIG_FILE"
			else
				echo -e "$red[!] Config file not found: $config_file${end}"
				exit 1
			fi
			shift ;;
		--update-config)
			update_config
			exit 0 ;;
		-h|--help)
			Usage;;
		-p|--parallel)
			PARALLEL=True ;;
		-v|--version)
			echo "Version: $VERSION"
			exit 0 ;;
		*)
			echo "[-] Unknown Option: $1"
			Usage ;;
	esac
	shift
done

[ "$silent" == False ] && echo -e $blue$bold"""
 ____        _     _____                       
/ ___| _   _| |__ | ____|_ __  _   _ _ __ ___  
\___ \| | | | '_ \|  _| | '_ \| | | | '_ \` _ \\ 
 ___) | |_| | |_) | |___| | | | |_| | | | | | |
|____/ \__,_|_.__/|_____|_| |_|\__,_|_| |_| |_|
           Subdomains Enumeration Tool
              By: bing0o @hack1lab
"""$end

Main
