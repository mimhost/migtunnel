
# vpn-script
testing phase

original script and conf by Horas

for Debian 9 & 10

apt update && apt upgrade -y && update-grub && sleep 2 && reboot

sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl && wget https://raw.githubusercontent.com/mimhost/migtunnel/main/setup.sh
 && ./setup.sh
