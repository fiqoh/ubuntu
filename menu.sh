#!/bin/bash

clear
echo -e ""
echo -e "[1]  Create User"
echo -e "[2]  Delete User"
echo -e "[3]  Check User Login"
echo -e "[4]  User List"
echo -e "[5]  Wireguard"
echo -e "[6]  Xray"
echo -e "[7]  Speedtest"
echo -e "[8]  Benchmark"
echo -e "[9]  Script Info"
echo -e "[x]  Exit"
echo -e ""
read -p "Select from options [1-9 or x] : " option

case $option in
	1)
	clear
	user-create
	exit
	;;
	2)
	clear
	user-delete
	exit
	;;
	3)
	clear
	user-login
	exit
	;;
	4)
	clear
	user-list
	exit
	;;
	5)
	clear
	user-wireguard
	exit
	;;
	6)
	clear
	xray-script
	exit
	;;
	7)
	clear
	speedtest
	echo -e ""
	exit
	;;
	8)
	clear
	echo -e ""
	wget -qO- wget.racing/nench.sh | bash
	;;
	9)
	clear
	script-info
	exit
	;;
	x)
	clear
	exit
	;;
	*)
	echo -e ""
	if [ -z $option ]; then
		echo -e "No input."
	else
		echo -e "Wrong input."
	fi
	echo -e ""
	exit
	;;
esac
