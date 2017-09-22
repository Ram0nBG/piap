#!/bin/bash
getPublicIP() {
if command -v dig &> /dev/null; then
    IPv4pub=$(dig +short myip.opendns.com @resolver1.opendns.com)
fi

    if [ -z "$IPv4pub" ]; then
        IPv4pub=$(curl -s eth0.me)
    fi

   if [ -z "$IPv4pub" ]; then
        echo "Couldnt get your Public IP"
   else
        echo -e "Public IP:\t\t"$IPv4pub
   fi

}

getRPi() {
declare -A arr
arr[0002]="Raspberry Pi 1 (Model B)"
arr[0003]="Raspberry Pi 1 (Model B)"
arr[0004]="Raspberry Pi 1 (Model B)"
arr[0005]="Raspberry Pi 1 (Model B)"
arr[0006]="Raspberry Pi 1 (Model B)"
arr[0007]="Raspberry Pi 1 (Model A)"
arr[0008]="Raspberry Pi 1 (Model A)"
arr[0009]="Raspberry Pi 1 (Model A)"
arr[000d]="Raspberry Pi 1 (Model B)"
arr[000e]="Raspberry Pi 1 (Model B)"
arr[000f]="Raspberry Pi 1 (Model B)"
arr[0010]="Raspberry Pi 1 (Model B+)"
arr[0013]="Raspberry Pi 1 (Model B+)"
arr[900032]="Raspberry Pi 1 (Model B+)"
arr[0012]="Raspberry Pi 1 (Model A+)"
arr[0015]="Raspberry Pi 1 (Model A+)"
arr[a01041]="Raspberry Pi 2 (Model B)"
arr[a21041]="Raspberry Pi 2 (Model B)"
arr[a22042]="Raspberry Pi 2 (Model B)"
arr[900092]="Raspberry Pi Zero"
arr[900093]="Raspberry Pi Zero"
arr[0x9000C1]="Raspberry Pi Zero W"
arr[a02082]="Raspberry Pi 3 (Model B)"
arr[a22082]="Raspberry Pi 3 (Model B)"
arr[a32082]="Raspberry Pi 3 (Model B)"

revision=$(cat /proc/cpuinfo | grep 'Revision' | awk '{ print $3 }' | sed 's/^1000//')

if [[ ${arr[$revision]} ]]; then
echo "${arr[$revision]}"
else
 echo 'unknown RPi'
fi

}

echo ''
getPublicIP
echo -e "Uptime:\t\t\t"$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes."}')
echo -e "wlan0 IP:\t\t"$(ifconfig wlan0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}')
echo -e "Running on:\t\t"$(getRPi)
echo -e "Size of / :\t\t"$(df -h / | awk 'NR==2 {print $2}')
