# ==========================================
# Getting
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
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/fb-vmessgrpc.json")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi
	
	clear
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/fb-vlessgrpc.json")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi
	
	clear
	echo ""
	echo " Select the existing client you want to remove"
	echo " Press CTRL+C to return"
	echo " ==============================="
	echo "     No  Expired   User"
	grep -E "^### " "/etc/xray/fb-vmessgrpc.json" | cut -d ' ' -f 2-3 | nl -s ') '
	grep -E "^### " "/etc/xray/fb-vlessgrpc.json" | cut -d ' ' -f 2-3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
user=$(grep -E "^### " "/etc/xray/fb-vmessgrpc.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/fb-vmessgrpc.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
user=$(grep -E "^### " "/etc/xray/fb-vlessgrpc.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/fb-vlessgrpc.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
sed -i "/^### $user $exp/,/^},{/d" /etc/xray/fb-vmessgrpc.json
sed -i "/^### $user $exp/,/^},{/d" /etc/xray/fb-vlessgrpc.json
rm -f /etc/xray/$user-tls.json
systemctl restart fb-vmess-grpc.service
systemctl restart fb-vless-grpc.service
clear
echo ""
echo -e "══════════════════════" | lolcat
echo "  XRAY GRPC VMESS VLESS Account Deleted  "
echo -e "══════════════════════" | lolcat
echo " Username  : $user"
echo " Expired   : $exp"
echo -e "══════════════════════" | lolcat
echo -e "${RED}AutoScriptSSH By MIGtunnel${NC}"
echo -e "══════════════════════" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi

