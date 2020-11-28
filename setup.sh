#!/bin/bash
#
# bash script to install SubEnum's dependencies 
#
GOlang() {
	printf "                                \r"
	sys=$(uname -m)
	[ $sys == "x86_64" ] && wget https://golang.org/dl/go1.15.2.linux-amd64.tar.gz -O golang.tar.gz &>/dev/null || wget https://golang.org/dl/go1.15.2.linux-386.tar.gz -O golang.tar.gz &>/dev/null
	sudo tar -C /usr/local -xzf golang.tar.gz
	echo "export GOROOT=/usr/local/go" >> $HOME/.profile
	echo "export GOPATH=$HOME/go" >> $HOME/.profile
	echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> $HOME/.profile
	echo 'source $HOME/.profile' >> $HOME/.zshrc
	echo 'source $HOME/.profile' >> $HOME/.bashrc
	
	printf "[+] Golang Installed !.\n"
}

Findomain() {
	printf "                                \r"
	wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux &>/dev/null
	chmod +x findomain-linux
	./findomain-linux &>/dev/null && { sudo mv findomain-linux /usr/local/bin/findomain; printf "[+] Findomain Installed !.\n"; } || printf "[!] Install Findomain manually: https://github.com/Findomain/Findomain/blob/master/docs/INSTALLATION.md\n"
}

Subfinder() {
	printf "                                \r"
	GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder &>/dev/null
	printf "[+] Subfinder Installed !.\n"
}

Amass() {
	printf "                                \r"
	GO111MODULE=on go get -v github.com/OWASP/Amass/v3/... &>/dev/null
	printf "[+] Amass Installed !.\n"
}

Assetfinder() {
	printf "                                \r"
	go get -u github.com/tomnomnom/assetfinder &>/dev/null
	printf "[+] Assetfinder Installed !.\n"
}

Httprobe() {
	printf "                                \r"
	go get -u github.com/tomnomnom/httprobe
	printf "[+] Httprobe Installed !.\n"
}

hash go 2>/dev/null && printf "[!] Golang is already installed.\n" || printf "[+] Installing GOlang!" && GOlang 
source $HOME/.bashrc 2>/dev/null
source $HOME/.zshrc 2>/dev/null

hash findomain 2>/dev/null && printf "[!] Findomain is already installed.\n" || { printf "[+] Installing Findomain!" && Findomain; }
hash subfinder 2>/dev/null && printf "[!] subfinder is already installed.\n" || { printf "[+] Installing subfinder!" && Subfinder; }
hash amass 2>/dev/null && printf "[!] Amass is already installed.\n" || { printf "[+] Installing Amass!" && Amass; }
hash assetfinder 2>/dev/null && printf "[!] Assetfinder is already installed.\n" || { printf "[+] Installing Assetfinder!" && Assetfinder; }
hash httprobe 2>/dev/null && printf "[!] Httprobe is already installed.\n" || { printf "[+] Installing Httprobe!" && Httprobe; }

list=(
	go
	findomain
	subfinder
	amass
	assetfinder
	httprobe
	)

r="\e[31m"
g="\e[32m"
e="\e[0m"

for prg in ${list[@]}
do
        hash $prg 2>/dev/null && printf "[$prg]$g Done$e\n" || printf "[$prg]$r Not Installed! Check Again.$e\n"
done
