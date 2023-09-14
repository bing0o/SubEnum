#!/bin/bash
#
# bash script to install SubEnum's dependencies 
#

GOlang() {
	printf "                                \r"
	sys=$(uname -m)
	#LATEST=$(curl -s 'https://go.dev/VERSION?m=text') # https://golang.org/dl/$LATEST.linux-amd64.tar.gz
	[ $sys == "x86_64" ] && wget https://go.dev/dl/go1.17.13.linux-amd64.tar.gz -O golang.tar.gz &>/dev/null || wget https://golang.org/dl/go1.17.13.linux-386.tar.gz -O golang.tar.gz &>/dev/null
	sudo tar -C /usr/local -xzf golang.tar.gz
	export GOROOT=/usr/local/go
	export GOPATH=$HOME/go
	export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
	echo "[!] Add The Following Lines To Your ~/.${SHELL##*/}rc file:"
 	echo 'export GOROOT=/usr/local/go'
  	echo 'export GOPATH=$HOME/go'
   	echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin'
	
	printf "[+] Golang Installed !.\n"
}

Findomain() {
	printf "                                \r"
	wget https://github.com/Findomain/Findomain/releases/download/8.2.1/findomain-linux.zip &>/dev/null
	unzip findomain-linux.zip
 	rm findomain-linux.zip
	chmod +x findomain
	./findomain -h &>/dev/null && { sudo mv findomain /usr/local/bin/; printf "[+] Findomain Installed !.\n"; } || printf "[!] Install Findomain manually: https://github.com/Findomain/Findomain/blob/master/docs/INSTALLATION.md\n"
}

Subfinder() {
	printf "                                \r"
	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &>/dev/null
	printf "[+] Subfinder Installed !.\n"
}

Amass() {
	printf "                                \r"
	go install -v github.com/owasp-amass/amass/v4/...@master &>/dev/null
	printf "[+] Amass Installed !.\n"
}

Assetfinder() {
	printf "                                \r"
	go install github.com/tomnomnom/assetfinder@latest &>/dev/null
	printf "[+] Assetfinder Installed !.\n"
}

Httprobe() {
	printf "                                \r"
	go install github.com/tomnomnom/httprobe@latest &>/dev/null
	printf "[+] Httprobe Installed !.\n"
}

Parallel() {
	printf "                                \r"
	sudo apt-get install parallel -y
	printf "[+] Parallel Installed !.\n"
}

Anew() {
	printf "                                \r"
	go install -v github.com/tomnomnom/anew@latest &>/dev/null
	printf "[+] Anew Installed !.\n"
}

hash go 2>/dev/null && printf "[!] Golang is already installed.\n" || { printf "[+] Installing GOlang!" && GOlang; } 


hash findomain 2>/dev/null && printf "[!] Findomain is already installed.\n" || { printf "[+] Installing Findomain!" && Findomain; }
hash subfinder 2>/dev/null && printf "[!] subfinder is already installed.\n" || { printf "[+] Installing subfinder!" && Subfinder; }
hash amass 2>/dev/null && printf "[!] Amass is already installed.\n" || { printf "[+] Installing Amass!" && Amass; }
hash assetfinder 2>/dev/null && printf "[!] Assetfinder is already installed.\n" || { printf "[+] Installing Assetfinder!" && Assetfinder; }
hash httprobe 2>/dev/null && printf "[!] Httprobe is already installed.\n" || { printf "[+] Installing Httprobe!" && Httprobe; }
hash parallel 2>/dev/null && printf "[!] Parallel is already installed.\n" || { printf "[+] Installing Parallel!" && Parallel; }
hash anew 2>/dev/null && printf "[!] Anew is already installed.\n" || { printf "[+] Installing Anew!" && Anew; }

list=(
	go
	findomain
	subfinder
	amass
	assetfinder
	httprobe
	parallel
 	anew
	)

r="\e[31m"
g="\e[32m"
e="\e[0m"

for prg in ${list[@]}
do
        hash $prg 2>/dev/null && printf "[$prg]$g Done$e\n" || printf "[$prg]$r Something Went Wrong! Try Again Manually.$e\n"
done
