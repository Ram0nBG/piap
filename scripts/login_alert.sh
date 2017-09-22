#!/bin/bash
IP=`echo $SSH_CONNECTION | cut -d " " -f 1`

if [ -n "$SSH_CLIENT" ]; then
        echo "huhu we got ourselfs a login, heh ? IP: $IP"
fi
