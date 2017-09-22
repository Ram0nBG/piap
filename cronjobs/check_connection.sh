#!/bin/bash

function pingGW() {
        ping -q -w 1 -c 1 `ip r | grep default | cut -d ' ' -f 3` > /dev/null && return 1 || return 0
        #ping -q -w 1 -c 1 `ip r | grep default | cut -d ' ' -f 3` > /dev/null && return 1 || ping -q -c 1 google.com && return 1 || return 0
}

internetConnection=$(pingGW)

if [[ $? < 1 ]];then
        INTERFACE=$(grep -i 'INTERFACE=.*' | sed 's/INTERFACE=//I' | /etc/.piap/config)
        if $(grep -o "[#]address=.*" /etc/dnsmasq.conf)
                sed -i  's/#\{0,\}address=.*//' /etc/dnsmasq.conf
        fi
        echo "address=/#/$(ifconfig $INTERFACE | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}')" >> /etc/dnsmasq.conf
        sudo service lighttpd start
        sudo service dnsmasq restart
        else
        echo "yepeee u have net"
fi
