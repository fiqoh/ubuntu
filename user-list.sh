#!/bin/bash

clear
echo -e ""
echo "-------------------------------"
echo "USERNAME          EXP DATE     "
echo "-------------------------------"
while read expired
do
        account="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $account | grep "Account expires" | awk -F": " '{print $2}')"
        if [[ $ID -ge 1000 ]]; then
        printf "%-17s %2s\n" "$account" "$exp"
        fi
done < /etc/passwd
total="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo "-------------------------------"
echo "Total accounts: $total user"
echo "-------------------------------"
echo -e ""