#!/bin/bash

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!" 
   exit 1
fi

# Update & Upgrade
apt-get update
apt-get upgrade -y

# Remove unused dependencies
apt-get autoremove -y

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

# Set timezone
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# Initialize variable
ipAddress=$(wget -qO- ipv4.icanhazip.com)

# Get domain
read -rp "Please enter your domain(eg: xray.iriszz.tk):" domain
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
echo -e "IP address by DNS resolver：${domain_ip}"
echo -e "Local public network IP address： ${ipAddress}"
sleep 2
if [[ ${domain_ip} == "${ipAddress}" ]]; then
	echo -e "The IP address by DNS resolver matches the local public network IP address."
	sleep 2
else
	print_error "Please make sure that the correct A record is added to the domain name, otherwise you will not be able to use xray normally."
	print_error "The IP address of the domain name resolved by DNS does not match the IP address of the machine. Do you want to continue the installation? (Y/n)" && read -r install
	case $install in
	[yY][eE][sS] | [yY])
		echo -e "Continue to install."
		sleep 2
		;;
		*)
		echo -e "Installation terminated."
		exit 2
		;;
	esac
fi

# Go to root directory
cd

# Install netstat
apt-get install -y net-tools

# Install vnstat
apt-get install -y vnstat

# Install screenfetch
wget -qO /usr/bin/screenfetch "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/screenfetch.sh"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile
echo "echo" >> .profile

# Install Dropbear
apt-get install -y dropbear
sed -i "s|NO_START=1|NO_START=0|g" /etc/default/dropbear
sed -i "s|DROPBEAR_PORT=22|DROPBEAR_PORT=85|g" /etc/default/dropbear
echo "/bin/false" >> /etc/shells
wget -qO /etc/issue.net "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/issue.net"
sed -i "s|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/issue.net"|g" /etc/default/dropbear
service dropbear restart

# Install Stunnel
apt install stunnel4 -y
sed -i "s|ENABLED=0|ENABLED=1|g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Iriszz/emailAddress=mail@iriszz.tk/O=Void VPN/OU=Void VPN Premium/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
wget -qO /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/stunnel.conf"
service stunnel4 restart

# Install Squid3
apt-get install -y squid3
wget -qO /etc/squid/squid.conf "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/squid.conf"
sed -i "s|ipAddress|$ipAddress|g" /etc/squid/squid.conf
service squid restart

# Install Webmin
wget -q http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
apt-get update
apt-get install -y webmin
sed -i "s|ssl=1|ssl=0|g" /etc/webmin/miniserv.conf
rm jcameron-key.asc
service webmin restart

# Install fail2ban
apt-get install -y fail2ban
service fail2ban restart

# Install Xray (Modded Script by Wulabing)
apt install -y lsb-release gnupg2 wget lsof tar unzip curl libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev jq nginx
curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
echo $domain >/usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/main/config/xray_tls_ws_mix-rprx-direct.json
[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
cat /usr/local/etc/xray/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >/usr/local/etc/xray/config_tmp.json
mv -f /usr/local/etc/xray/config_tmp.json /usr/local/etc/xray/config.json
cat /usr/local/etc/xray/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >/usr/local/etc/xray/config_tmp.json
mv -f /usr/local/etc/xray/config_tmp.json /usr/local/etc/xray/config.json
cat /usr/local/etc/xray/config.json | jq 'setpath(["inbounds",0,"port"];'443')' >/usr/local/etc/xray/config_tmp.json
mv -f /usr/local/etc/xray/config_tmp.json /usr/local/etc/xray/config.json
cat /usr/local/etc/xray/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'/xray/'")' >/usr/local/etc/xray/config_tmp.json
mv -f /usr/local/etc/xray/config_tmp.json /usr/local/etc/xray/config.json
cat /usr/local/etc/xray/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'/xray/'")' >/usr/local/etc/xray/config_tmp.json
mv -f /usr/local/etc/xray/config_tmp.json /usr/local/etc/xray/config.json
wget -O /etc/nginx/conf.d/${domain}.conf https://raw.githubusercontent.com/wulabing/Xray_onekey/main/config/web.conf
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
systemctl restart nginx
mkdir -p /www/xray_web
wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
tar xzf web.tar.gz -C /www/xray_web
rm -f web.tar.gz
signedcert=$(xray tls cert -domain="$ipAddress" -name="$ipAddress" -org="$ipAddress" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem
echo $signedcert | jq '.key[]' | sed 's/\"//g' >/usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /ssl
cp -a /usr/local/etc/xray/self_signed_cert.pem /ssl/xray.crt
cp -a /usr/local/etc/xray/self_signed_key.pem /ssl/xray.key
curl -L get.acme.sh | bash
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
sed -i "6s/^/#/" "/etc/nginx/conf.d/${domain}.conf"
sed -i "6a\\\troot /www/xray_web/;" "/etc/nginx/conf.d/${domain}.conf"
systemctl restart nginx
"$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/www/xray_web/" -k ec-256 --force
"$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force
sed -i "7d" /etc/nginx/conf.d/${domain}.conf
sed -i "6s/#//" /etc/nginx/conf.d/${domain}.conf
chown -R nobody.nogroup /ssl/*
systemctl restart nginx
systemctl restart xray

# Install OpenVPN
apt-get install -y openvpn
wget -q https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/openvpn/EasyRSA-3.0.8.tgz
tar xvf EasyRSA-3.0.8.tgz
rm EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_COUNTRY\t"US"|set_var EASYRSA_REQ_COUNTRY\t"MY"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_PROVINCE\t"California"|set_var EASYRSA_REQ_PROVINCE\t"Pulau Pinang"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_CITY\t"San Francisco"|set_var EASYRSA_REQ_CITY\t"Bukit Mertajam"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"|set_var EASYRSA_REQ_ORG\t\t"Void VPN"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_EMAIL\t"me@example.net"|set_var EASYRSA_REQ_EMAIL\t"mail@iriszz.tk"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"|set_var EASYRSA_REQ_OU\t\t"Void VPN Premium"|g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-dh
./easyrsa gen-req server nopass
./easyrsa sign-req server server
openvpn --genkey --secret pki/private/ta.key
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/ta.key /etc/openvpn/key/
wget -qO /etc/openvpn/server-udp.conf "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/openvpn/server-udp.conf"
wget -qO /etc/openvpn/server-tcp.conf "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/openvpn/server-tcp.conf"
sed -i "s|#AUTOSTART="all"|AUTOSTART="all"|g" /etc/default/openvpn
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp

# Configure OpenVPN client configuration
wget -qO /var/www/html/client-udp.ovpn "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/openvpn/client-udp.ovpn"
wget -qO /var/www/html/client-tcp.ovpn "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/openvpn/client-tcp.ovpn"
sed -i "s|xxx.xxx.xxx.xxx|$ipAddress|g" /var/www/html/client-udp.ovpn
sed -i "s|xxx.xxx.xxx.xxx|$ipAddress|g" /var/www/html/client-tcp.ovpn
echo "" >> /var/www/html/client-tcp.ovpn
echo "<ca>" >> /var/www/html/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /var/www/html/client-tcp.ovpn
echo "</ca>" >> /var/www/html/client-tcp.ovpn
echo "" >> /var/www/html/client-udp.ovpn
echo "<ca>" >> /var/www/html/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /var/www/html/client-udp.ovpn
echo "</ca>" >> /var/www/html/client-udp.ovpn

# Install WireGuard
apt-get install -y wireguard iptables resolvconf qrencode
mkdir /etc/wireguard >/dev/null 2>&1
chmod 600 -R /etc/wireguard/
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
echo "SERVER_PUB_IP=$ipAddress
SERVER_PUB_NIC=eth0
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_PORT=51820
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=8.8.8.8
CLIENT_DNS_2=8.8.4.4" >/etc/wireguard/params
source /etc/wireguard/params
echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wg.conf
sysctl --system
systemctl start "wg-quick@${SERVER_WG_NIC}"
systemctl enable "wg-quick@${SERVER_WG_NIC}"
mkdir ~/wg-config

# Install BadVPN UDPGw
cd
apt-get install -y cmake
wget -q https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/badvpn.zip
unzip badvpn.zip
cd badvpn-master
mkdir build-badvpn
cd build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -r badvpn-master
rm badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# Install Speedtest cli
curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash
apt-get install speedtest

# Configure UFW
apt-get install -y ufw
echo "" >> /etc/ufw/before.rules
echo "# START OPENVPN RULES" >> /etc/ufw/before.rules
echo "# NAT table rules" >> /etc/ufw/before.rules
echo "*nat" >> /etc/ufw/before.rules
echo ":POSTROUTING ACCEPT [0:0]" >> /etc/ufw/before.rules
echo "# Allow traffic from OpenVPN client to eth0" >> /etc/ufw/before.rules
echo "-I POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE" >> /etc/ufw/before.rules
echo "-I POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE" >> /etc/ufw/before.rules
echo "COMMIT" >> /etc/ufw/before.rules
echo "# END OPENVPN RULES" >> /etc/ufw/before.rules
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|g' /etc/default/ufw
sed -i "s|IPV6=yes|IPV6=no|g" /etc/default/ufw
ufw allow 22
ufw allow 1194
ufw allow 80
ufw allow 443
ufw allow 465
ufw allow 8080
ufw allow 51820
ufw allow 85
ufw allow 7300
ufw allow 10000
ufw disable
echo "y" | ufw enable
ufw reload

# Configure rc.local
wget -qO /etc/rc.local "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/rc.local"
chmod +x /etc/rc.local

# Configure menu
wget -qO /usr/bin/menu "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/menu.sh"
wget -qO /usr/bin/user-create "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/user-create.sh"
wget -qO /usr/bin/user-delete "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/user-delete.sh"
wget -qO /usr/bin/user-list "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/user-list.sh"
wget -qO /usr/bin/user-login "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/user-login.sh"
wget -qO /usr/bin/script-info "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/script-info.sh"
wget -qO /usr/bin/user-wireguard "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/user-wireguard.sh"
wget -qO /usr/bin/xray-script "https://raw.githubusercontent.com/iriszz-my/autoscript/main/FILES/menu/xray-script.sh"
chmod +x /usr/bin/{menu,user-create,user-delete,user-list,user-login,script-info,user-wireguard,xray-script}

# Configure auto-reboot
echo "0 0 * * * root reboot" >> /etc/crontab

# Print info about script
if [ "$(cat /sys/module/ipv6/parameters/disable)" -ge 1 ]; then
	ipv6_status="ON"
else
	ipv6_status="OFF"
fi
timezone="$(timedatectl | grep -i 'Time zone' | awk '{print $3}')"
ufwstatus="$(ufw status | grep Status | awk '{print $2}')"
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(netstat -nlpt | grep -i squid | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
xrayport="$(netstat -nlpt | grep -i xray | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
badvpnport="$(netstat -nlpt | grep -i badvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
wireguardport="$(wg | grep -i port | awk '{print $3}')"
nginxport="$(netstat -nlpt | grep -i nginx | grep -i -m1 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

clear
echo ""
echo "IPv6 : [$ipv6_status]"
echo "Timezone : [$timezone]"
echo "UFW : [$ufwstatus]"
echo "Reboot : [12 AM]"
echo ""
echo "Port OpenSSH : [$opensshport]"
echo "Port Dropbear : [$dropbearport]"
echo "Port Stunnel : [$stunnel4port]"
echo "Port Squid : [$squidport]"
echo "Port OpenVPN : [$openvpnport]"
echo "Port Xray : [$xrayport]"
echo "Port BadVPN-UDPGw : [$badvpnport]"
echo "Port Nginx : [$nginxport]"
echo "Port WireGuard : [$wireguardport]"
echo ""
echo "Webmin : http://$ipAddress:10000/"
echo ""
echo "OVPN Config:"
echo "http://$ipAddress/client-udp.ovpn"
echo "http://$ipAddress/client-tcp.ovpn"
echo ""
echo "Telegram: @Iriszz"
echo ""

# Cleanup and reboot
read -n 1 -r -s -p $'Press enter to reboot...\n'
rm -f ~/autoscript.sh
cp /dev/null ~/.bash_history
reboot
