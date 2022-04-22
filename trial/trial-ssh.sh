#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(wget -qO- ipinfo.io/ip);
now=`date +"%Y-%m-%d"`
echo "Checking VPS"

clear
echo -e "════════════════════════════" | lolcat
echo -e "  ${red}Create Trial SSH & OpenVpn Account${NC}"
echo -e "════════════════════════════" | lolcat
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
IP=$(wget -qO- ipinfo.io/ip);
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
MYIP=$(wget -qO- ipinfo.io/ip);
ssl="$(cat ~/log-install.txt | grep -w "Stunnel5" | cut -d: -f2)"
sqd="$(cat ~/log-install.txt | grep -w "Squid" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
Login=trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari="1"
Pass=1
echo Ping Host
echo Cek Hak Akses...
sleep 0.5
echo Permission Accepted
clear
sleep 0.5
echo Membuat Akun: $Login
sleep 0.5
echo Setting Password: $Pass
sleep 0.5
clear
tnggl=$(date +"%R")
read -p "Expired (Jam): " ktf
exp1=`date -d "$ktf hour" +"%R"`
useradd -e `date -d "$ktf hour" +"%R"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e ""
echo -e "════════════════════════" | lolcat
echo -e "Berikut Adalah Informasi" | lolcat
echo -e "Akun SSH & OpenVPN TRIAL By ${domain}" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "Username       : $Login " | lolcat
echo -e "Password       : $Pass" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "Domain         :${domain}" | lolcat
echo -e "Host           :$IP" | lolcat
echo -e "OpenSSH        : 22" | lolcat
echo -e "Dropbear       : 2443, 109, 143" | lolcat
echo -e "SSL/TLS        :$ssl" | lolcat
echo -e "Port Squid     :$sqd" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "Port SSH CDN   : 2082" | lolcat
echo -e "Port CDN TLS   : 2443" | lolcat
echo -e "Port CDN OVPN  : 2086" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "OpenVPN        : TCP $ovpn http://$IP:89/client-tcp-$ovpn.ovpn" | lolcat
echo -e "OpenVPN        : UDP $ovpn2 http://$IP:89/client-udp-$ovpn2.ovpn" | lolcat
echo -e "OpenVPN        : SSL 990 http://$IP:89/client-tcp-ssl.ovpn" | lolcat
echo -e "badvpn         : 7100-7300" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "PAYLOAD WS DB" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "GET / HTTP/1.1[crlf]Host: ${domain}[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "PAYLOAD WS SSL" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "GET ${domain}:// bug.com/ HTTP/1.1[crlf]Host: ${domain}[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "Created        : $now" | lolcat
echo -e "Expired On     : jam $ktf" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "AutoScript By MIGtunnel" | lolcat
echo -e "════════════════════════" | lolcat
echo -e "~ Beli Dong Masa Engga Hehehe ~" | lolcat
echo -e "~ Garansi 30Hari ~" | lolcat
echo -e "~ Mulai Dari Tanggal Pembelian ~" | lolcat
echo -e "~ Terimakasih Selamat Menikmati ~" | lolcat
echo -e""
read -p "Ketik Enter Untuk Kembali Ke Menu...."
sleep 1
menu
exit 0
fi
