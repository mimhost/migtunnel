#!/bin/bash
grey='\x1b[90m'
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
yellow='\x1b[93m'
blue='\x1b[94m'
purple='\x1b[95m'
cyan='\x1b[96m'
white='\x1b[37m'
bold='\033[1m'
off='\x1b[m'
flag='\x1b[47;41m'
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
MYIP=$(wget -qO- ipinfo.io/ip);
now=`date +"%Y-%m-%d"`
echo "Checking VPS"

clear
echo -e "════════════════════════════" | lolcat
echo -e "    ${red}Create Trial Vmess Account${NC}"
echo -e "════════════════════════════" | lolcat
source /var/lib/crot/ipvps.conf
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
read -rp "Masukkan Bug: " -e bug
tls="$(cat ~/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
nontls="$(cat ~/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"
user=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c2`
uuid=$(cat /proc/sys/kernel/random/uuid)
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
exp=`date -d "$ktf hour" +"%R"`
sed -i '/#xray-vmess-tls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"32"',"email": "'""$user""'"' /etc/xray/config.json
sed -i '/#xray-vmess-nontls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"32"',"email": "'""$user""'"' /etc/xray/config.json
cat>/etc/xray/vmess-$user-tls.json<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "${tls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/Ronggolawe",
      "type": "none",
      "host": "${bug}",
      "tls": "tls"
}
EOF
cat>/etc/xray/vmess-$user-nontls.json<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${bug}",
      "port": "${nontls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/Ronggolawe",
      "type": "none",
      "host": "${domain}",
      "tls": "none"
}
EOF
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
xrayv2ray1="vmess://$(base64 -w 0 /etc/xray/vmess-$user-tls.json)"
xrayv2ray2="vmess://$(base64 -w 0 /etc/xray/vmess-$user-nontls.json)"
systemctl restart xray.service
service cron restart
clear
echo -e ""
echo -e " ╠══════════════════════════╣" | lolcat
echo -e " ║         ${red}TRIAL-VMESS${NC}           ║"
echo -e " ╠══════════════════════════╣" | lolcat
echo -e "Remarks     : ${user}"
echo -e "IP/Host     : ${MYIP}"
echo -e "Address     : ${domain}"
echo -e "Port TLS    : ${tls}"
echo -e "Port No TLS : ${nontls}"
echo -e "User ID     : ${uuid}"
echo -e "Alter ID    : 0"
echo -e "Security    : auto"
echo -e "Network     : ws"
echo -e "Bug         : ${bug}"
echo -e "Path        : /Ronggolawe"
echo -e "═══════════════════════" | lolcat
echo -e "${red}VMESS-TLS${NC}"
echo -e "═══════════════════════" | lolcat
echo -e ""
echo -e " ${xrayv2ray1}" | lolcat
echo -e ""
echo -e "═══════════════════════" | lolcat
echo -e "${red}VMESS-NONTLS${NC}"
echo -e "═══════════════════════" | lolcat
echo -e ""
echo -e " ${xrayv2ray2}" | lolcat
echo -e ""
echo -e "═══════════════════════" | lolcat
echo -e " >>>Created            : $now" | lolcat
echo -e " >>>Active During To   : $ktf Jam" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e ""
echo -e "═══════════════════════" | lolcat
echo -e "${red}AutoScriptSSH By MIGtunnel${NC}"
echo -e "═══════════════════════" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi
