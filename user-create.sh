#!/bin/bash

opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(netstat -nlpt | grep -i squid | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
badvpnport="$(netstat -nlpt | grep -i badvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

clear
echo -e ""
read -p "Username      : " login
if getent passwd $login > /dev/null 2>&1; then
	echo ""
	echo "Username '$login' already exist!"
	echo ""
	exit 0
fi
read -p "Password      : " pass
read -p "Expired (days): " expired
useradd -e `date -d "$expired days" +"%Y-%m-%d"` -s /bin/false -M $login

IP=$(wget -qO- ipv4.icanhazip.com)
exp="$(chage -l $login | grep "Account expires" | awk -F": " '{print $2}')"

clear
echo -e "$pass\n$pass\n"|passwd $login &> /dev/null
echo -e ""
echo -e "===SSH Account Information==="
echo -e "Host: $IP"
echo -e "Port OpenSSH: $opensshport"
echo -e "Port Dropbear: $dropbearport"
echo -e "Port Stunnel: $stunnel4port"
echo -e "Port OpenVPN: $openvpnport"
echo -e "Port Squid: $squidport"
echo -e "Port BadVPN-UDPGw: $badvpnport"
echo -e ""
echo -e "Username: $login "
echo -e "Password: $pass"
echo -e ""
echo -e "OVPN Config:"
echo -e "http://$IP/client-udp.ovpn"
echo -e "http://$IP/client-tcp.ovpn"
echo -e "-----------------------------"
echo -e "Expired date: $exp"
echo -e "============================="
echo -e ""
