#!/bin/bash

# For a fast configuration, you can type in your domain name
DOMAIN_NAME="example.com"
# The name of this server eg. "vpn-server"
SERVER_NAME="srv"

DEFAULT_EDITOR="vim"

###### Settings and Constants
# Define the default destination folder of the ZIP files
# Destination can be overridden with the -c parameter
# ZIP files are password protected
ZIP_DESTINATION="/tmp"

# 1: Creates an all in one file, for easier handling
# 0: Certificates and config are divided in seperated files
SINGLE_CERT=1

# If the value is set to 1, it will always set the debug parameter
DEBUG=1

SUBNET_IP="10.250.0.0"
SUBNET_MASK="255.255.255.0"
USER_IP_RANGE="10.250.0.101-10.250.0.250"

# Specify the interface which is connected to the internet
GATEWAY_INTERFACE="eth0"

# To apply the rules: run "versa rebuild"
GROUPS_ENABLED=1

gi=0
GROUP_NAME[$gi]="gateway" #Name of the VLAN rule
GROUP_VLAN_RULE[$gi]="-o $GATEWAY_INTERFACE -j ACCEPT" #iptables rule (iptables -A CHAIN -s U_IP ) must not be defined
GROUP_CONF_RULE[$gi]="push 'redirect-gateway def1 bypass-dhcp';block-outside-dns"

gi=$(($gi +1))
GROUP_NAME[$gi]="server"
GROUP_SERVER_RULE[$gi]="-j ACCEPT" #Allows all users in group "server" to access everything on this server

gi=$(($gi +1))
GROUP_NAME[$gi]="admin" #Allows all users in group "admin" to access just everything
GROUP_VLAN_RULE[$gi]="-j ACCEPT"
GROUP_SERVER_RULE[$gi]="-j ACCEPT"

gi=$(($gi +1))
GROUP_NAME[$gi]="gaming"
GROUP_VLAN_RULE[$gi]="-j TARGET" #All Clients with access to the gaming group can reach all targets of the gaming group

gi=$(($gi +1))
GROUP_NAME[$gi]="infrastructure"
GROUP_VLAN_RULE[$gi]="-j TARGET"

# Specify the internal Domain Name as a prefix
# Example: If the domain name is "clients.example.com" a new client "test" can
# be reached with "test.clients.example.com" and just "test"
DNS_LONG_PREFIX=".c.$DOMAIN_NAME"
DNS_SHORT_PREFIX=".c"

export OPENVPN_PATH="/etc/openvpn"

# Default 2048 Bits
export KEY_SIZE=4096

# Value in Days
export CA_EXPIRE=3650
export KEY_EXPIRE=730

export KEY_COUNTRY="DE"
export KEY_PROVINCE="NRW"
export KEY_CITY="Cologne"
export KEY_ORG="$DOMAIN_NAME"
export KEY_EMAIL="vpn@$DOMAIN_NAME"
export KEY_OU="${DOMAIN_NAME}OU"
export KEY_NAME="$DOMAIN_NAME"
