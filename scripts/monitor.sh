#!/bin/sh

# IFACE=wlp5s0b1
# IFACE=wlxb8eca3dec4d4
IFACE=wlan1

# /bin/systemctl stop NetworkManager.service
# /bin/systemctl stop wpa_supplicant.service

/sbin/ip link set $IFACE down
/sbin/iw dev $IFACE set type monitor
/sbin/ip link set $IFACE up
/sbin/iw dev $IFACE set channel 6
/sbin/iw dev $IFACE info

