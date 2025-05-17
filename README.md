## Description:
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-9-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

bash script for Subdomain Enumeration using 4 tools and 3 online services, you have to install these tools by yourself to be able to use SubEnum.sh, or use [setup.sh](https://github.com/bing0o/SubEnum/blob/master/setup.sh) script to install them.

![image](img.png)

### Available Tools and online services:

1. Tools:
	- [Findomain](https://github.com/Edu4rdSHL/findomain)
	- [SubFinder](https://github.com/projectdiscovery/subfinder)
	- [Amass](https://github.com/OWASP/Amass)
	- [AssetFinder](https://github.com/tomnomnom/assetfinder)
	- [Sublist3r](https://github.com/aboul3la/Sublist3r)
	- [Gobuster](https://github.com/OJ/gobuster) - DNS mode for subdomain brute forcing
	- [DNSGen](https://github.com/ProjectAnte/dnsgen) - For generating domain permutations
	- [anew](https://github.com/tomnomnom/anew): To delete duplicates when using -s/--silent option.
	- [Dnsx](https://github.com/projectdiscovery/dnsx): To resolve found subdomains.
    - [Httprobe](https://github.com/tomnomnom/httprobe): To Probe For Working HTTP and HTTPS 
	 Subdomains.
	
2. Online services:
	- [WayBackMachine](http://web.archive.org/)
	- [crt.sh](https://crt.sh/)
	- [AbuseIPDB](https://www.abuseipdb.com/)
	- [HackerTarget](https://hackertarget.com/)
	- [RapidDNS](https://rapiddns.io/)
	- [Riddler](https://riddler.io/)
	- [CertSpotter](https://sslmate.com/certspotter/)
	- [AlienVault OTX](https://otx.alienvault.com/)
	- [ThreatCrowd](https://www.threatcrowd.org/)

3. Services that require API keys:
	- [SecurityTrails](https://securitytrails.com/) - Requires `SECURITYTRAILS_API_KEY` to be set
	- [GitHub](https://github.com/) - Improved with `GITHUB_TOKEN` if available
	- [VirusTotal](https://www.virustotal.com/) - Requires `VT_API_KEY` to be set
	- [Chaos](https://chaos.projectdiscovery.io/) - Requires `CHAOS_API_KEY` to be set

## Installation:

to install the dependencies run:

```bash
$ git clone https://github.com/bing0o/SubEnum.git
$ cd SubEnum
$ chmod +x setup.sh
$ ./setup.sh
```

## Usage:

### Basic usage:

```bash
$ subenum -d target.com 
```

### Resolve The Found Subdomains:

```bash
$ subenum -d target.com -r 
```

### Agains a list of domains

```bash
$ subenum -l domains.txt -r
```

### Exclude:

```bash
$ subenum -d target.com -e Amass,wayback
```

### Use:

```bash
$ subenum -d target.com -u Findomain,Subfinder
```

exclude and use can be used with list of domains too 

```bash
$ subenum -l domains.txt -u crt,bufferover
```

### Parallel:
the tool `parallel` must be installed on you system, it runs all the functions at the same time which make the results faster, doesn't work with -u/--use or -e/--exclude options.

```bash
$ subenum -d target.com -p
```


### Silent:

this option helps when you want to pipe the results to another tool, or just to avoid the useless output.

```bash
$ subenum -d target.com -s 
dev.target.com
admin.target.com
api.target.com
..
..
```

happy hacking!


## Spport:

You can support me here:

<a href="https://www.buymeacoffee.com/bing0o" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/secfb"><img src="https://avatars2.githubusercontent.com/u/38748801?v=4?s=100" width="100px;" alt="Never Mind"/><br /><sub><b>Never Mind</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=secfb" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mehedi1194"><img src="https://avatars2.githubusercontent.com/u/54717234?v=4?s=100" width="100px;" alt="Mehedi Hasan Remon"/><br /><sub><b>Mehedi Hasan Remon</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=mehedi1194" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://alins.ir"><img src="https://avatars.githubusercontent.com/u/67107893?v=4?s=100" width="100px;" alt="alins.ir"/><br /><sub><b>alins.ir</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=alins1r" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://0xhunster.github.io"><img src="https://avatars.githubusercontent.com/u/46501627?v=4?s=100" width="100px;" alt="Akash Sarkar"/><br /><sub><b>Akash Sarkar</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=0xhunster" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://twitter.com/cihanmehmets"><img src="https://avatars.githubusercontent.com/u/7144304?v=4?s=100" width="100px;" alt="Cihan Mehmet DOĞAN (CMD)"/><br /><sub><b>Cihan Mehmet DOĞAN (CMD)</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=cihanmehmet" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Q0120S"><img src="https://avatars.githubusercontent.com/u/72891022?v=4?s=100" width="100px;" alt="NoobHunter"/><br /><sub><b>NoobHunter</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=Q0120S" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://bug-hunter.tk"><img src="https://avatars.githubusercontent.com/u/94289484?v=4?s=100" width="100px;" alt="Sharo_k_h"/><br /><sub><b>Sharo_k_h</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=SharokhAtaie" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://mujtabasec.github.io/"><img src="https://avatars.githubusercontent.com/u/72700323?v=4?s=100" width="100px;" alt="Mujtaba"/><br /><sub><b>Mujtaba</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=mujtabasec" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Psikoz-coder"><img src="https://avatars.githubusercontent.com/u/200380657?v=4?s=100" width="100px;" alt="Psikoz"/><br /><sub><b>Psikoz</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=Psikoz-coder" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ibrahimsql"><img src="https://avatars.githubusercontent.com/u/ibrahimsql?v=4?s=100" width="100px;" alt="ibrahimsql"/><br /><sub><b>ibrahimsql</b></sub></a><br /><a href="https://github.com/bing0o/SubEnum/commits?author=ibrahimsql" title="Code">💻</a></td>
	    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
