#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
MYIP=$(wget -qO- ipinfo.io/ip);
now=`date +"%Y-%m-%d"`
echo "Checking VPS"

clear
echo -e "════════════════════════════" | lolcat
echo -e "    ${red}Create Trial-Vless Account${NC}"
echo -e "════════════════════════════" | lolcat
source /var/lib/crot/ipvps.conf
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
read -rp "Masukkan Bug: " -e bug
tls="$(cat ~/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
nontls="$(cat ~/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"
user=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c2`
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
		read -rp "Username : " -e user
		CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo -e "Username ${red}${user}${NC} Already On VPS Please Choose Another"
			exit 1
		fi
	done
uuid=$(cat /proc/sys/kernel/random/uuid)
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
exp=`date -d "$ktf hour" +"%R"`
sed -i '/#xray-vless-tls$/a\#### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
sed -i '/#xray-vless-nontls$/a\#### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
xrayvless1="vless://${uuid}@${domain}:$tls?path=/Ronggolawe&security=tls&encryption=none&type=ws#${user}"
xrayvless2="vless://${uuid}@${domain}:$nontls?path=/Ronggolawe&encryption=none&type=ws#${user}"
systemctl restart xray.service
service cron restart
clear
echo -e ""
echo -e " ╠══════════════════════════╣" | lolcat
echo -e " ║          ${red}TRIAL-VLESS${NC}          ║"
echo -e " ╠══════════════════════════╣" | lolcat
echo -e "Remarks     : ${user}"
echo -e "IP/Host     : ${MYIP}"
echo -e "Address     : ${domain}"
echo -e "Port TLS    : $tls"
echo -e "Port No TLS : $nontls"
echo -e "User ID     : ${uuid}"
echo -e "Encryption  : none"
echo -e "Network     : ws"
echo -e "Bug.        : ${bug}"
echo -e "Path        : /Ronggolawe"
echo -e "═══════════════════════" | lolcat
echo -e "Link TLS    : "
echo -e ""
echo -e " ${xrayvless1}"
echo -e "═══════════════════════" | lolcat
echo -e "Link No TLS : "
echo -e ""
echo -e " ${xrayvless2}"
echo -e "═══════════════════════" | lolcat
echo -e "Created        : $now" | lolcat
echo -e "Active During To : $ktf Hours" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e "${red}AutoScriptSSH By MIGtunnel${NC}"
echo -e "═══════════════════════" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi
