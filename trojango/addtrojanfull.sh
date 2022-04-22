#!/bin/bash
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"

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
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
		read -rp "Password : " -e user
		user_EXISTS=$(grep -w $user /etc/trojan-go/akun.conf | wc -l)

		if [[ ${user_EXISTS} == '1' ]]; then
			echo ""
			echo -e "Username ${RED}${user}${NC} Already On VPS Please Choose Another"
			exit 1
		fi
	done
read -p "Expired (Days) : " masaaktif
sed -i '/"'""$uuid""'"$/a\,"'""$user""'"' /etc/trojan-go/config.json
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
hariini=`date -d "0 days" +"%Y-%m-%d"`
echo -e "### $user $exp" >> /etc/trojan-go/akun.conf
systemctl restart trojan-go.service
link="trojan-go://${user}@${bug}:${trgo}/?sni=${domain}&type=ws&host=${domain}&path=/migtunnel&encryption=none#$user"
link1="trojan://${user}@${bug}:8443/?sni=${domain}&type=ws&host=${domain}&path=/migtunnel&encryption=none#$user"
link2="trojan://${user}@${bug}:8880/?sni=&type=ws&host=${domain}&path=/migtunnel&encryption=none#$user"
clear
echo -e ""
echo -e "════════════════" | lolcat
echo -e "${RED}=====-TROJAN-Websocket-====${NC}"
echo -e "════════════════" | lolcat
echo -e "Remarks    : ${user}"
echo -e "IP/Host    : ${MYIP}"
echo -e "Address    : ${domain}"
echo -e "Port trgo  : ${trgo}"
echo -e "Port wstls : 8443"
echo -e "Port wsnone: 8880"
echo -e "Key        : ${user}"
echo -e "Encryption : none"
echo -e "Bug.       : ${bug}
echo -e "Path       : /Ronggolawe"
echo -e "Created    : $hariini"
echo -e "Expired    : $exp"
echo -e "════════════════" | lolcat
echo -e "Link Trojan-WsNone  : 
echo -e ""
echo -e " ${link2}"
echo -e "════════════════" | lolcat
echo -e "Link Trojan-WsTLS  : 
echo -e ""
echo -e " ${link1}"
echo -e "════════════════" | lolcat
echo -e "Link Trojan-go  : 
echo -e ""
echo -e " ${link}"
echo -e "════════════════" | lolcat
echo -e "${RED}AutoScriptSSH By MIGtunnel${NC}"
echo -e "════════════════" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi
