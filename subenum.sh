#!/bin/bash
#
# script for subdomain enumeration using 4 of the best tools with some APIs:
#   * findomain: https://github.com/Edu4rdSHL/findomain
#   * SubFinder: https://github.com/projectdiscovery/subfinder
#   * Amass: https://github.com/OWASP/Amass
#   * AssetFinder: https://github.com/tomnomnom/assetfinder
#
# a perl version is being developed by @terminalforlife 
#   * https://github.com/terminalforlife/PerlProjects/tree/master/source/dominator
#

bold="\e[1m"
Underlined="\e[4m"
red="\e[31m"
green="\e[32m"
blue="\e[34m"
#grey="\e[90m"
end="\e[0m"
ugb=""
VERSION="2020-04-07"

PRG=${0##*/}

echo -e $blue$bold"
 ____        _     _____                       
/ ___| _   _| |__ | ____|_ __  _   _ _ __ ___  
\___ \| | | | '_ \|  _| | '_ \| | | | '_ \` _ \\ 
 ___) | |_| | |_) | |___| | | | |_| | | | | | |
|____/ \__,_|_.__/|_____|_| |_|\__,_|_| |_| |_|
           SubDomains enumeration tool
              By: bing0o @hack1lab
"$end

Usage(){
	while read -r line; do
		printf "%b\n" "$line"
	done <<-EOF
	\r$blue
	\r#Options:
	\r 	-d, --domain\t Domain To Enumerate
	\r	-u, --use\t Tools To Be Used ex(Findomain,Subfinder,...,etc)
	\r	-l, --list\t List of domains
	\r	-e, --exclude\t Tools To Be Excluded ex(Findomain,Amass,...,etc)
	\r	-o, --output\t The output file to save the Final Results (Default: alldomains-<TargetName>)
	\r	-k, --keep\t To Keep the TMPs files (the results from each tool).
	\r	-v, --version\t Displays the version and exit.
	\r	-h, --help\t Displays this help message and exit.

	\r#Available Tools:
	\r	wayback,crt,bufferover,Findomain,Subfinder,Amass,Assetfinder

	\r#Example:
	\r	- To use a specific Tools:
	\r		$PRG -d hackerone.com -u Findomain,wayback,Subfinder
	\r	- To exclude a specific Tools:
	\r		$PRG -d hackerone.com -e Amass,Assetfinder
	\r	- To use all the Tools:
	\r		$PRG -d hackerone.com $end 
EOF
	exit 1
}


wayback() { 
	echo -e "$bold[+] WayBackMachine$end"
	curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > tmp-wayback-$domain
	echo -e "[*] Results: $(wc -l tmp-wayback-$domain)\n" 	
}

crt() {
	echo -e "$bold[+] crt.sh$end"
	curl -sk "https://crt.sh/?q=%.$domain&output=json&exclude=expired" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > tmp-crt-$domain
	echo -e "[*] Results: $(wc -l tmp-crt-$domain)\n" 
}

bufferover() {
	echo -e $bold"[+] BufferOver"$end
	curl -s "https://dns.bufferover.run/dns?q=.$domain" | grep $domain | awk -F, '{gsub("\"", "", $2); print $2}' | sort -u > tmp-bufferover-$domain
	echo -e "[*] Results: $(wc -l tmp-bufferover-$domain)\n"
}

Findomain() {
	echo -e $bold"[+] Findomain"$end
	findomain -t $domain -u tmp-findomain-$domain &>/dev/null
	echo -e "[*] Results: $(wc -l tmp-findomain-$domain 2>/dev/null)\n"
}

Subfinder() {
	echo -e $bold"[+] SubFinder"$end
	subfinder -silent -d $domain 1> tmp-subfinder-$domain 2>/dev/null
	echo -e "[*] Results: $(wc -l tmp-subfinder-$domain)\n"
}



Amass() {
	echo -e $bold"[+] Amass"$end
	amass enum -norecursive -noalts -d $domain 1> tmp-amass-$domain 2>/dev/null
	echo -e "[*] Results: $(wc -l tmp-amass-$domain)\n"
}

Assetfinder() {
	echo -e $bold"[+] Assetfinder"$end
	assetfinder --subs-only $domain > tmp-assetfinder-$domain
	echo -e "[*] Results: $(wc -l tmp-assetfinder-$domain)\n"
}




USE() {
	for i in $lu; do
		$i
	done
	OUT
}


EXCLUDE() {
	for i in ${list[@]}; do
		if [[ " ${le[@]} " =~ " ${i} " ]]; then
			continue
		else
			$i
		fi
	done
	OUT
}

OUT(){
	[ -n "$1" ] && out="$1" || out="$domain-$(date +'%Y-%m-%d-%H%M%S').txt"
	sort -u tmp-* > $out
	echo -e $green"[+] The Final Results:$end $(wc -l $out)\n"

	[ $delete == True ] && rm tmp-*	
}

LIST() {
	lines=$(wc -l < $hosts)
	count=1
	while read domain; do
		echo -e "$Underlined$bold$green[+] Domain ($count/$lines):$end $domain"
		[ $prv == "a" ] && {
			wayback
			crt
			bufferover
			Findomain 
			Subfinder 
			Amass 
			Assetfinder
			OUT
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
		[ $use == False ] && [ $exclude == False ] && { 
			wayback
			crt
			bufferover
			Findomain 
			Subfinder 
			Amass 
			Assetfinder
			OUT
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


domain=False
hosts=False
use=False
exclude=False
delete=True
out=False

list=(
	wayback
	crt
	bufferover
	Findomain 
	Subfinder 
	Amass 
	Assetfinder
	)

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
		-k|--keep)
			delete=False ;;
		-h|--help)
			Usage;;
		-v|--version)
			echo "Version: $VERSION"
			exit 0 ;;
		*)
			echo "[-] Unknown Option: $1"
			Usage;;
	esac
	shift
done

Main
