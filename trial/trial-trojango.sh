#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(wget -qO- ipinfo.io/ip);
KATA=$(curl -s rdpvps.me/kata.php )
echo "Checking VPS"

clear
echo -e "════════════════════════════" | lolcat
echo -e "    ${red}Create Trial Trojan-Go Account${NC}"
echo -e "════════════════════════════" | lolcat
sleep 2
MYIP=$(wget -qO- ipinfo.io/ip);
clear
uuid=$(cat /etc/trojan-go/uuid.txt)
source /var/lib/crot/ipvps.conf
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
read -rp "Masukkan Bug: " -e bug
trgo="$(cat ~/log-install.txt | grep -w "TrojanGo" | cut -d: -f2|sed 's/ //g')"
user=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c2`
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
		read -rp "Password : " -e user
		user_EXISTS=$(grep -w $user /etc/trojan-go/akun.conf | wc -l)

		if [[ ${user_EXISTS} == '1' ]]; then
			echo ""
			echo -e "Username ${red}${user}${NC} Already On VPS Please Choose Another"
			exit 1
		fi
	done
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
sed -i '/"'""$uuid""'"$/a\,"'""$user""'"' /etc/trojan-go/config.json
exp=`date -d "$ktf hour" +"%R"`
echo -e "### $user $exp" >> /etc/trojan-go/akun.conf
systemctl restart trojan-go.service
link="trojan-go://${user}@${bug}:${trgo}/?sni=${domain}&type=ws&host=${domain}&path=/trojango&encryption=none#$user"
clear
echo
echo -e " ╠═════════════════════════╣" | lolcat
echo -e " ║        ${red}TRIAL-TROJANGO${NC}        ║"
echo -e " ╠═════════════════════════╣" | lolcat
echo -e "Remarks    : ${user}"
echo -e "IP/Host    : ${MYIP}"
echo -e "Address    : ${domain}"
echo -e "Port       : ${trgo}"
echo -e "Key        : ${user}"
echo -e "Encryption : none"
echo -e "Bug.       : ${bug}
echo -e "Path       : /trojango"
echo -e "Created     : $now" | lolcat
echo -e "Active During To : $ktf Hours" | lolcat
echo -e "══════════════════════════" | lolcat
echo -e "Link        : ${trogolink}" | lolcat
echo -e "══════════════════════════" | lolcat
echo -e "════════-Config Yaml-═══════" | lolcat
echo -e "══════════════════════════" | lolcat
echo -e "proxies:" | lolcat
echo -e "  - name: TrojanGo"
echo -e "    server: ${bug}" | lolcat
echo -e "    port: ${trgo}" | lolcat
echo -e "    password: ${user}" | lolcat
echo -e "    network: ws" | lolcat
echo -e "    sni: ${domain}" | lolcat
echo -e "    skip-cert-verify: true" | lolcat
echo -e "    udp: true" | lolcat
echo -e "    ws-opts:" | lolcat
echo -e "     path: /trojan-go" | lolcat
echo -e "     headers:" | lolcat
echo -e "      Host: ${domain}" | lolcat
echo -e "════════════════════════════" | lolcat
echo -e "${red}AutoScriptSSH By MIGtunnel${NC}"
echo -e "════════════════════════════" | lolcat
echo -e "~ Selamat Berselancar Broh..!!!" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi
