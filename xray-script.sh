#!/bin/bash

# Initialize variables
UUID=$(cat /usr/local/etc/xray/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
PORT=$(cat /usr/local/etc/xray/config.json | jq .inbounds[0].port)
FLOW=$(cat /usr/local/etc/xray/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
WS_PATH=$(cat /usr/local/etc/xray/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')
DOMAIN=$(cat /usr/local/etc/xray/domain)

function showConfig() {
	echo -e ""
	echo -e "Xray Configuration"
	echo -e "=================="
	echo -e "( VLESS + WebSocket + TLS )"
	echo -e "Host: $DOMAIN"
	echo -e "Server Port: $PORT"
	echo -e "User ID: $UUID"
	echo -e "Security: none"
	echo -e "Network Type: ws"
	echo -e "WebSocket Path: $WS_PATH"
	echo -e "TLS: tls"
	echo -e ""
	echo -e "( VLESS + WebSocket + TLS / XTLS )"
	echo -e "Adress: $DOMAIN"
	echo -e "Port: $PORT"
	echo -e "ID: $UUID"
	echo -e "Flow: $FLOW"
	echo -e "Encryption: none"
	echo -e "Network: tcp"
	echo -e "Head Type: none"
	echo -e "TLS: tls / xtls"
	echo -e ""
	echo -e "Link:"
	echo -e "-----"
	echo -e "( VLESS + TCP + TLS )"
	echo -e "vless://$UUID@$DOMAIN:$PORT?security=tls#TLS-$DOMAIN"
	echo -e ""
	echo -e "( VLESS + TCP + XTLS )"
	echo -e "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS-$DOMAIN"
	echo -e ""
	echo -e "( VLESS + WebSocket + TLS )"
	echo -e "vless://$UUID@$DOMAIN:$PORT?type=ws&security=tls&path=%2f${WS_PATH_WITHOUT_SLASH}%2f#WS_TLS-$DOMAIN"
	echo -e ""
	echo -e "QR code:"
	echo -e "--------"
	echo -e "( VLESS + TCP + TLS )"
	echo -e "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%23TLS-$DOMAIN"
	echo -e ""
	echo -e "( VLESS + TCP + XTLS )"
	echo -e "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS-$DOMAIN"
	echo -e ""
	echo -e "( VLESS + WebSocket + TLS )"
	echo -e "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?type=ws%26security=tls%26path=%2f${WS_PATH_WITHOUT_SLASH}%2f%23WS_TLS-$DOMAIN"
	echo -e ""
}

function showLog() {
	tail -f /var/log/xray/access.log
}

function renewSSL() {
	"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
	systemctl restart nginx
	systemctl restart xray
}

clear
echo -e ""
echo -e "[1]  Show Xray configuration"
echo -e "[2]  Show real-time access log"
echo -e "[3]  Renew SSL manually"
echo -e "[4]  Exit"
echo -e ""
until [[ ${MENU_OPTION} =~ ^[1-3]$ ]]; do
	read -rp "Select an option [1-3]: " MENU_OPTION
done
case "${MENU_OPTION}" in
1)
	clear
	showConfig
	;;
2)
	clear
	showLog
	;;
3)
	clear
	renewSSL
	;;
4)
	clear
	exit 0
	;;
esac
