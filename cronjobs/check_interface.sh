#!/bin/bash
IP=$(ifconfig $INTERFACE | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}')
if [ -z $IP ]; then
        echo ':: $INTERFACE has no IP address at the moment. Restarting the interface ::'
        sudo ifdown $INTERFACE
        sudo ifup $INTERFACE
else
        echo ':: wlan0 is ok ::' $IP
fi
