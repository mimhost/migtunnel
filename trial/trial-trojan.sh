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
echo -e "  ${red}Create Trial Trojan-GFW Account${NC}"
echo -e "════════════════════════════" | lolcat
uuid=$(cat /etc/trojan/uuid.txt)
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
if [[ "$IPHost" = "" ]]; then
PUBLIC_IP=$(wget -qO- ipv4.icanhazip.com);
else
PUBLIC_IP=$IPHost
fi
read -rp "Masukkan Bug: " -e bug
tr="$(cat ~/log-install.txt | grep -w "Trojan" | cut -d: -f2|sed 's/ //g')"
user=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c2`
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
		read -rp "Password : " -e user
		user_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

		if [[ ${user_EXISTS} == '1' ]]; then
			echo ""
			echo -e "Username ${red}${user}${NC} Already On VPS Please Choose Another"
			exit 1
		fi
	done
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
sed -i '/#xray-trojan$/a\#&# '"$user $exp"'\
},{"password": "'""$user""'","email": "'""$user""'"' /etc/xray/config.json
exp=`date -d "$ktf hour" +"%R"`
systemctl restart xray.service
trojanlink="trojan://${user}@${domain}:${tr}/${bug}"
trojanlinkk="trojan://${user}@${PUBLIC_IP}:${tr}/${bug}"
service cron restart
clear
echo -e ""
echo -e " ╠══════════════════════════╣" | lolcat
echo -e " ║         ${red}TRIAL-TROJAN${NC}          ║"
echo -e " ╠══════════════════════════╣" | lolcat
echo -e "Remarks  : ${user}"
echo -e "IP/Host  : ${PUBLIC_IP}"
echo -e "Address  : ${domain}"
echo -e "Port     : ${tr}"
echo -e "Key      : ${user}"
echo -e "Bug     : ${bug}"
echo -e "════════════════════════" | lolcat
echo -e "Link TR  : ${trojanlink}" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e "Link TR IP  : ${trojanlink}" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e "Created          : $now" | lolcat
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
