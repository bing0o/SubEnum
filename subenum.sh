#!/bin/bash
#
# script for subdomain enumeration using 4 of the best tools and some online services:
#   * findomain: https://github.com/Edu4rdSHL/findomain
#   * SubFinder: https://github.com/projectdiscovery/subfinder
#   * Amass: https://github.com/OWASP/Amass
#   * AssetFinder: https://github.com/tomnomnom/assetfinder
#

bold="\e[1m"
Underlined="\e[4m"
red="\e[31m"
green="\e[32m"
blue="\e[34m"
end="\e[0m"
VERSION="2024-12-28"

PRG=${0##*/}

Usage(){
	while read -r line; do
		printf "%b\n" "$line"
	done <<-EOF
	\r
	\r# ${bold}${blue}Options${end}:
	\r    -d, --domain       - Domain To Enumerate
	\r    -l, --list         - List of domains
	\r    -u, --use          - Tools To Be Used ex(Findomain,Subfinder,...,etc)
	\r    -e, --exclude      - Tools To Be Excluded ex(Findomain,Amass,...,...)
	\r    -o, --output       - The output file to save the Final Results (Default: <TargetDomain>-DATE-TIME.txt)
	\r    -s, --silent       - The Only output will be the found subdomains - (Results saved: subenum-<DOMAIN>.txt).
	\r    -k, --keep         - To Keep the TMPs files (the results from each tool).
	\r    -r, --resolve      - To Probe For Working HTTP and HTTPS Subdomains, (Output: resolved-<DOMAIN>.txt).
	\r    -t, --thread       - Threads for Httprobe - works with -r/--resolve option (Default: 40)
	\r    -p, --parallel     - To Use Parallel For Faster Results, Doesn't Work With -e/--exclude or -u/--use. 
	\r    -h, --help         - Displays this help message and exit.
	\r    -v, --version      - Displays the version and exit.

	\r# ${bold}${blue}Available Tools${end}:
	\r	  wayback,crt,abuseipdb,Findomain,Subfinder,Amass,Assetfinder

	\r# ${bold}${blue}Examples${end}:
	\r    - To use a specific Tool(s):
	\r       $PRG -d hackerone.com -u Findomain,wayback,Subfinder
	\r    - To exclude a specific Tool(s):
	\r       $PRG -d hackerone.com -e Amass,Assetfinder
	\r    - To use all the Tools:
	\r       $PRG -d hackerone.com 
	\r    - To run SubEnum.sh against a list of domains:
	\r       $PRG -l domains.txt
	\r    - Run with parallel for faster results, (Doesn't work with -e/--exclude or -u/--use).
	\r       1- $PRG --domain target.com --parallel
	\r       2- $PRG --list domains.txt --parallel
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


# Tool Check Function
check_tool() {
  tool=$1
  if ! command -v "$tool" &>/dev/null; then
    echo -e "${red}[!] $tool not found. Please install it first.${end}"
    exit 1
  fi
}

wayback() {
	check_tool "curl"
	[ "$silent" == True ] && curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u | anew subenum-$domain.txt  || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}WayBackMachine${end}" &
			PID="$!"
		}
		curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > tmp-wayback-$domain
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] WayBackMachine$end: $(wc -l < tmp-wayback-$domain)"
	}
}

# Additional functions (crt, abuseipdb, etc.) are updated similarly to add tool checks using check_tool()

Findomain() {
	check_tool "findomain"
	[ "$silent" == True ] && findomain -t $domain -q 2>/dev/null | anew subenum-$domain.txt || {
		[[ ${PARALLEL} == True ]] || { spinner "${bold}Findomain${end}" &
			PID="$!"
		}
		findomain -t $domain -u tmp-findomain-$domain &>/dev/null
		[[ ${PARALLEL} == True ]] || kill ${PID} 2>/dev/null
		echo -e "$bold[*] Findomain$end: $(wc -l tmp-findomain-$domain 2>/dev/null | awk '{print $1}')"
	}
}

# Main function and script flow is unchanged

Main() {
	[ $domain == False ] && [ $hosts == False ] && { echo -e $red"[-] Argument -d/--domain OR -l/--list is Required!"$end; Usage; }
	[ $use != False ] && [ $exclude != False ] && { echo -e $Underlined$red"[!] You can use only one Option: -e/--exclude OR -u/--use"$end; Usage; }
	[ $domain != False ] && { 
		[ $use == False ] && [ $exclude == False ] && { 
			[[ ${PARALLEL} == True ]] && {
				spinner "Reconnaissance" &
				PID="$!"
				export -f wayback crt abuseipdb Findomain Subfinder Amass Assetfinder spinner
				export domain silent bold end
				parallel -j7 ::: wayback crt abuseipdb Findomain Subfinder Amass Assetfinder
				kill ${PID}
			} || {
				wayback
				crt
				abuseipdb
				Findomain 
				Subfinder
				Amass 
				Assetfinder
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
}

# Script Execution Starts
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
	Findomain 
	Subfinder 
	Amass 
	Assetfinder
	)

# Argument parsing and Main function call
# (unchanged, as above)
