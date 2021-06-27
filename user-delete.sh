#!/bin/bash

clear
echo -e ""
read -p "Delete user: " login
echo -e ""

if getent passwd $login > /dev/null 2>&1; then
	userdel $login
	echo -e "User '$login' has been deleted successfully."
	echo -e ""
else
	echo -e "User '$login' does not exist."
	echo -e ""
fi