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
echo -e "    ${red}Create Trial GRPC Account${NC}"
echo -e "════════════════════════════" | lolcat
source /var/lib/crot/ipvps.conf
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
read -rp "Masukkan Bug: " -e bug
tls=$(cat /etc/xray/vmessgrpc.json | grep port | awk '{print $2}' | sed 's/,//g')
vl=$(cat /etc/xray/vlessgrpc.json | grep port | awk '{print $2}' | sed 's/,//g')
user=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c2`
uuid=$(cat /proc/sys/kernel/random/uuid)
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
exp=`date -d "$ktf hour" +"%R"`
sed -i '/#vmessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /etc/xray/vmessgrpc.json
sed -i '/#vlessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/vlessgrpc.json
cat > /etc/xray/$user-tls.json << EOF
      {
      "v": "0",
      "ps": "${user}",
      "add": "${domain}",
      "port": "${tls}",
      "id": "${uuid}",
      "aid": "0",
      "net": "grpc",
      "path": "GunService",
      "type": "none",
      "host": "${bug}",
      "tls": "tls"
}
EOF
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmesslink1="vmess://$(base64 -w 0 /etc/xray/$user-tls.json)"
vlesslink1="vless://${uuid}@${domain}:${vl}?mode=gun&security=tls&encryption=none&type=grpc&serviceName=GunService&sni=${bug}#$user"
systemctl restart vmess-grpc.service
systemctl restart vless-grpc.service
service cron restart
clear
echo -e ""
echo -e " ╠══════════════════════════╣" | lolcat
echo -e " ║         ${red}TRIAL-GRPC${NC}           ║"
echo -e " ╠══════════════════════════╣" | lolcat
echo -e "Remarks           : ${user}" | lolcat
echo -e "Domain            : ${domain}" | lolcat
echo -e "Port VMess        : ${tls}" | lolcat
echo -e "Port VLess        : ${vl}" | lolcat
echo -e "ID                : ${uuid}" | lolcat
echo -e "Alter ID          : 0" | lolcat
echo -e "Mode              : Gun" | lolcat
echo -e "Security          : TLS" | lolcat
echo -e "Type              : grpc" | lolcat
echo -e "Service Name      : GunService" | lolcat
echo -e "SNI               : ${bug}" | lolcat
echo -e "═══════════════════════" | lolcat
echo -e "${red}VMESS-GRPC${NC}"
echo -e "═══════════════════════" | lolcat
echo -e ""
echo -e "${vmesslink1}" | lolcat
echo -e ""
echo -e "═══════════════════════" | lolcat
echo -e "${red}VLESS-GRPC${NC}"
echo -e "═══════════════════════" | lolcat
echo -e ""
echo -e "${vlesslink1}" | lolcat
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
