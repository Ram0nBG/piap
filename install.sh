#!/usr/bin/env bash
# Wireless router & VPN

export SUDO="sudo"
NEEDED_PACKAGES="hostapd dnsmasq lighttpd"
DNS_SERVER_CONF="config/dnsmasq.conf"
HOSTAPD_CONFIG="/etc/hostapd/hostapd.conf"
INTERFACE=""
APP_DIR="/etc/.piap"
APP_NAME="PIAP"
#default values
AP_DNS1=8.8.8.8
AP_DNS2=8.8.4.4
AP_DHCP_START=192.168.5.2
AP_DHCP_END=192.168.5.99
AP_STATIC_IP=192.168.5.1
AP_STATIC_IP_SUBNET=255.255.255.0
AP_SSID="PIAP"
AP_SSID_PSWD="secret123"
OS_VERSION=$(cat /etc/debian_version)


welcome() {
	whiptail --title "SCRIPT" --msgbox "This script is gonna transform your Pi into an Access Point with a VPN support" 8 78
}

welcomeText() {
	echo -e "\e[92m###############################################"
	echo -e "\e[92m##                                           ##"
	echo -e "\e[92m##   .______    __       ___      .______    ##"
	echo -e "\e[92m##   |   _  \  |  |     /   \     |   _  \   ##"
	echo -e "\e[92m##   |  |_)  | |  |    /  ^  \    |  |_)  |  ##"
	echo -e "\e[92m##   |   ___/  |  |   /  /_\  \   |   ___/   ##"
	echo -e "\e[92m##   |  |      |  |  /  _____  \  |  |       ##"
	echo -e "\e[92m##   | _|      |__| /__/     \__\ | _|       ##"
	echo -e "\e[92m##                                           ##"
	echo -e "\e[92m##					    ##"
	echo -e "\e[92m###############################################\033[0m"
	echo ""
}

boot() {
	if [ "$EUID" -ne 0 ];then
        	echoError "please run with sudo"
        	exit 1
	fi


	if [ -f $APP_DIR/installing ];then
		echoError "The installing script is already running"
		exit 1
	fi


	if [[ ${OS_VERSION:0:1} < 8 ]];then
		echoError "Detected an unsupported version of your Operating System"
		exit 1
	fi


	mkdir -p $APP_DIR/logs
	mkdir -p $APP_DIR/cronjobs
	# make log file
	touch $APP_DIR/logs/installation
	touch $APP_DIR/boot
	touch $APP_DIR/installing
	echo '1' > $APP_DIR/boot
	echo '1' > $APP_DIR/installing

	logAction "Started installation" "installation"
	welcomeText
	welcome
	chooseInterface
	setStaticIP
}

updatePackages() {
	sudo apt-get update
}

abortScript() {
	sudo rm -f $APP_DIR/installing
}

chooseInterface() {

availableInterfaces=$( ip -o link | grep -E "state (UP|DOWN)" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
mode="OFF"
count=1
num=1
options=''


declare -A interfaces

for interface in $availableInterfaces;
        do
        interfaces[$num]=$interface
        let num=num+1
done


for interface in $availableInterfaces;
        do
        if [ $count -eq 1 ]; then
                mode="ON"
        else
                mode="OFF"
        fi
        options+="$count $interface $mode "
        let count=count+1
done



option=$(whiptail --title "Choose your interface" --radiolist "Interfaces" --cancel-button "Cancel installation" 20 78 $count $options 2>&1 >/dev/tty)

if [[ $? > 0 ]]; then
	whiptail --title "SCRIPT" --msgbox "You cancelled the installation process. Nothing will be installed" 8 78
	abortScript
	exit 1;
fi

if !(whiptail --title "Confirmation" --no-button "Change interface" --yesno "${interfaces[$option]} will be the interface for your Access Point. Continue ?" 8 78) then
	chooseInterface
fi

INTERFACE=${interfaces[$option]}

logAction "Setting the interface to: $INTERFACE" "installation"

}

setStaticIP() {
	if (whiptail --title "Static IP" --no-button "Skip" --yesno "In the next section you will be able to set a Static IP for the $INTERFACE interface. If you want the system to do it automatically for you, just press Next" 8 78) then
		#GET STATIC IP
		IP=$(whiptail --inputbox "Type your Static IP" 8 78 --title "Tell us your IP" 3>&1 1>&2 2>&3)
		#GET THE SUBNET
		NETMASK=$(whiptail --inputbox "Netmask" 8 78 --title "Subnet" 3>&1 1>&2 2>&3)
	else
		IP=$AP_STATIC_IP
		NETMASK=$AP_STATIC_IP_SUBNET
	fi
if ! [[ $(grep -q -E "^denyinterfaces $INTERFACE$" /etc/dhcpcd.conf) ]];then
	$SUDO echo "#tell dhcpcd to ignore $INTERFACE interface" >> /etc/dhcpcd.conf
	$SUDO echo "denyinterfaces $INTERFACE" >> /etc/dhcpcd.conf
fi

sed -i "s/iface \[INTERFACE\] inet static/iface $INTERFACE inet static/" config/interfaces
sed -i "s/address \[IP\]/address $IP/" config/interfaces
sed -i "s/netmask \[NETMASK\]/netmask $NETMASK/" config/interfaces

logAction "Setting a static IP address for $INTERFACE to $IP with a subnet $NETMASK" "installation"

}

configure_WiFi() {
	if (whiptail --title "Configure WiFi" --no-button "Skip" --yesno "Would you like to configure your WiFi now ?" 8 78) then
		#GET SSID
		if PARAM=$(whiptail --inputbox "The name of the WiFi network you want to connect" 8 78 --title "SSID" 3>&1 1>&2 2>&3)
		then
        		SSID=$PARAM
		fi
		#GET PASSWORD
		if PARAM=$(whiptail --passwordbox "Password" 8 78 --title "Password" 3>&1 1>&2 2>&3)
		then
        		PASSWORD=$PARAM
		fi

$SUDO cat <<EOF > /etc/wpa_supplicant/wpa_supplicant.conf
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid=$SSID
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP TKIP
    group=CCMP TKIP
    psk=$PASSWORD
}
EOF
	fi
}

#http://www.linuxjournal.com/content/validating-ip-address-bash-script
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}


setup_DHCP_SERVER() {
MANUAL=0
		if (whiptail --title "Enable DHCP" --yesno "Would you like to configure your DHCP Server now ?" 8 78) then
			MANUAL=1
			#START RANGE
			PARAM=$(whiptail --inputbox --no-button "Skip" "Start range" 8 78 --title "Configure DHCP" 3>&1 1>&2 2>&3)
			if valid_ip $PARAM && [[ $? == 0 ]];then
        			START_RANGE=$PARAM
			else
        			START_RANGE=$AP_DHCP_START
			fi
			#END RANGE
			PARAM=$(whiptail --inputbox --no-button "Skip" "End range" 8 78 --title "Configure DHCP" 3>&1 1>&2 2>&3)
			if valid_ip $PARAM && [[ $? == 0 ]];then
        			END_RANGE=$PARAM
			else
        			END_RANGE=$AP_DHCP_END
			fi
			#DNS SERVER 1
			PARAM=$(whiptail --inputbox --no-button "Skip" "DNS SERVER" 8 78 --title "Configure DHCP" 3>&1 1>&2 2>&3)
			if valid_ip $PARAM && [[ $? == 0 ]];then
        			NS1=$PARAM
			else
        			NS1=$AP_DNS1
			fi
			#DNS SERVER 2
			PARAM=$(whiptail --inputbox --no-button "Skip" "Second DNS SERVER" 8 78 --title "Configure DHCP" 3>&1 1>&2 2>&3)
			if valid_ip $PARAM && [[ $? == 0 ]];then
        			NS2=$PARAM
			else
        			NS2=$AP_DNS2
			fi

		else
			START_RANGE=$AP_DHCP_START
			END_RANGE=$AP_DHCP_END
			NS1=$AP_DNS1
			NS2=$AP_DNS2
		fi
		
		if [[ $MANUAL = 1 ]];then
			if !(whiptail --title "Confirmation" --yes-button "Continue" --no-button "Change settings" --yesno "DHCP range is: $START_RANGE - $END_RANGE \nDNS Servers are: $NS1 and $NS2 \n Continue ?" 8 78) then
				setup_DHCP_SERVER
			fi
		fi

sed -i "s/interface=\[INTERFACE\]/interface=$INTERFACE/" $DNS_SERVER_CONF
sed -i "s/server=\[NS1\]/server=$NS1/" $DNS_SERVER_CONF
sed -i "s/server=\[NS2\]/server=$NS2/" $DNS_SERVER_CONF
sed -i "s/dhcp-range=interface:\[INTERFACE\],\[START_RANGE\],\[END_RANGE\],12h/dhcp-range=interface:$INTERFACE,$START_RANGE,$END_RANGE,12h/" $DNS_SERVER_CONF

logAction "DHCP Server enabled and configured" "installation"

}

enableIPForwarding() {
    sudo sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
    sudo sysctl -p &> /dev/null
}

configureIPTables() {
	if ! [[ $(sudo iptables-save | grep -- "-A POSTROUTING -o eth0 -j MASQUERADE") ]];then
		sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	fi
	if ! [[ $(sudo iptables-save | grep -- "-A FORWARD -i eth0 -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT") ]];then
		sudo iptables -A FORWARD -i eth0 -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
	fi
	if ! [[ $(sudo iptables-save | grep -- "-A FORWARD -i $INTERFACE -o eth0 -j ACCEPT") ]];then
		sudo iptables -A FORWARD -i $INTERFACE -o eth0 -j ACCEPT
	fi

	$SUDO sh -c "iptables-save > $APP_DIR/iptables.rules"

	$SUDO echo "pre-up iptables-restore < $APP_DIR/iptables.rules" >> /etc/network/interfaces

	logAction "IPtables configured" "installation"
}

createHostapdConfig() {
	touch $HOSTAPD_CONFIG
	# Tell hostapd where to look for the config file when it starts up on boot
	sed -i 's/#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/g' /etc/default/hostapd
}

setAccessPointName() {
			SSID=$(whiptail --nocancel --inputbox "SSID" 8 78 --title "SSID" 3>&1 1>&2 2>&3)
			_SSID=${SSID// }
			if [[ ${#_SSID} -lt 1 || $? > 0 ]];then
				setAccessPointName
			else
				echo $SSID
			fi
}

setAccessPointPassword() {
			PSWD=$(whiptail --nocancel --inputbox "Password (at least 8 symbols)" 8 78 --title "Password" 3>&1 1>&2 2>&3)
			_PSWD=${PSWD// }
			if [[ ${#_PSWD} -lt 8 || $? > 0 ]]; then
				setAccessPointPassword
			else
				echo $PSWD
			fi
}

configureHostapd() {
	if (whiptail --title "SCRIPT" --yesno --no-button "Skip" "Do you want to configure your Access Point or let the system do it for you ?" 8 78) then
		#SSID
		SSID=$(setAccessPointName)
		#PASSWORD
		PSWD=$(setAccessPointPassword)
	else
		SSID=$AP_SSID
		PSWD=$AP_SSID_PSWD
	fi

#changing default values to the current one
AP_SSID=$SSID
AP_SSID_PSWD=$PSWD


#Generates passphrase
PASSPHRASE=$(wpa_passphrase $SSID $PSWD | sed -nE 's/^[[:blank:]]+psk=(.*)/\1/p')

sed -i "s/interface=\[INTERFACE\]/interface=$INTERFACE/" config/hostapd.conf
sed -i "s/ssid=\[SSID\]/ssid=$SSID/" config/hostapd.conf
sed -i "s/wpa_psk=\[PASSPHRASE\]/wpa_psk=$PASSPHRASE/" config/hostapd.conf

logAction "hostapd configured" "installation"
}

makeCronjobs() {
	mv cronjobs/check_interface.sh $APP_DIR/cronjobs/check_interface.sh

	file=file-$(date +%s)
	touch $file
	crontab -l > $file
	if grep -q "$APP_DIR/cronjobs/check_interface.sh" "$file"; then
		sed -i /'* * * * * \/bin\/bash $APP_DIR\/cronjobs\/check_interface.sh'/d $file
	fi

	echo '* * * * * /bin/sh $APP_DIR/cronjobs/check_interface.sh' >> $file
	crontab $file
	rm -f $file

	logAction "cronjob configured" "installation"
}

getDate() {
        echo $(date "+%b %d %H:%M:%S")
}

logAction() {
 date=$(getDate)
 echo ".:: $date ::." $1 >> $APP_DIR/logs/$2
}

echoInfo() {
	echo -e "\e[92m.:: $1 ::."
}

echoError() {
	echo -e "\e[91m.:: $1 ::."
}

install() {
	if command -v debconf-apt-progress &> /dev/null; then
		sudo debconf-apt-progress -- apt-get install $NEEDED_PACKAGES -y
	else
		sudo apt-get install $NEEDED_PACKAGES -y
	fi

	if [[ $? > 0 ]]
	then
		echoError "Installation stopped: Cannot install needed packages. Check your connection ?"
		logAction "Installation stopped: Cannot install $NEEDED_PACKAGES" installation
		abortScript
		exit 1
	else
		logAction "successfully installed: $NEEDED_PACKAGES" installation
	fi

	# stop the services
	sudo service dnsmasq stop
	sudo service hostapd stop
	sudo service lighttpd stop
}

installScripts() {
	sudo cp /etc/motd /etc/motd.old
	sudo rm /etc/motd
	sudo echo "" > /etc/motd
 	sudo mv scripts/piap_motd.sh /etc/profile.d/piap_motd.sh
	sudo mv scripts/login_alert.sh /etc/profile.d/login_alert.sh
	sudo mv scripts/piap /usr/local/bin/piap
	sudo chmod 755 /usr/local/bin/piap
}

finish() {
	echoInfo "Finishing the installation"
	sudo cp /etc/network/interfaces /etc/network/interfaces.old
	sudo mv config/interfaces /etc/network/interfaces

	sudo service dhcpcd restart
	sudo ifdown $INTERFACE
	sudo ifup $INTERFACE
	#insert iptables rules
	configureIPTables

	#moving all configuration files
	sudo mv config/dnsmasq.conf /etc/dnsmasq.conf
	sudo mv config/hostapd.conf /etc/hostapd/hostapd.conf
	# enable ip forwarding
	enableIPForwarding
	# get hostapd and dnsmasq to start on boot
	sudo update-rc.d hostapd enable
	sudo update-rc.d dnsmasq enable

	# start the services
	sudo service dnsmasq start
	sudo service hostapd start
	#$SUDO nohup /usr/sbin/hostapd -B $HOSTAPD_CONFIG 

	sudo rm -f $APP_DIR/installing
  
	echo "THERE'S NO INTERNET CONNECTION" > /var/www/html/index.html

	logAction "$APP_NAME installed successfully" "installation"

	echoInfo "$APP_NAME was successfully installed !"
	echo ""
	echoInfo "SSID: $AP_SSID"
	echoInfo "PASSWORD: $AP_SSID_PSWD"
}


boot
#configure_WiFi
setup_DHCP_SERVER
configureHostapd
install
createHostapdConfig
installScripts
finish
