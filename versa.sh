#!/bin/bash
#
# OpenVPN      Very Easy RSA Usermanagement Script
# Author:      Rene Fa
# Version:     1.6.8
# Date:        12.05.2018
# Licence:     GNU Lesser General Public Licence

source /etc/versa/config.sh

# These values must not be changed
FP="/tmp/versa-v-stdout" # Path for the verbose named pipe

# OpenVPN config
OPENVPN_CONF() {
cat <<EOF
port 1194
proto udp
dev tun
ca versa/rootCA.crt
cert versa/server.crt
key versa/server.key  # This file should be kept secret
dh versa/dh.pem
crl-verify versa/crl.pem
topology subnet

# Configure your desired subnet here
server $SUBNET_IP $SUBNET_MASK
ifconfig-pool-persist ipp.txt

#Push Traffic through VPN
#push "redirect-gateway def1 bypass-dhcp"

push "dhcp-option DNS $SERVER_IP"
push "dhcp-option DNS 80.80.80.80"

client-config-dir ccd
push "route 10.250.0.0 255.255.255.0"
#client-to-client

auth-user-pass-verify versa/verify.sh via-file

script-security 2

keepalive 10 120
cipher AES-256-CBC   # AES
comp-lzo
user nobody
group nogroup
persist-key
persist-tun

status openvpn-status.log
verb 3
EOF
}

OPENVPN_CLIENT_CONF() {

PUBLIC_IP="$(cat $OPENVPN_PATH/versa/publicip)"

cat <<EOF
#daemon 1
client
dev tun
proto udp
remote $PUBLIC_IP 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
mute-replay-warnings
ns-cert-type server
cipher AES-256-CBC
comp-lzo
verb 3

## If you use Linux
#script-security 2
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf

## If you use Linux with systemd-resolved (eg. >= Ubuntu 16.10 )
#script-security 2
#setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#up /etc/openvpn/scripts/update-systemd-resolved
#down /etc/openvpn/scripts/update-systemd-resolved
#down-pre

auth-user-pass
#auth-user-pass authfile
EOF
}

OPENSSL_CONF() {
cat <<EOF
HOME                    = .
RANDFILE                = \$ENV::HOME/.rnd
oid_section             = new_oids
[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7
[ ca ]
default_ca      = CA_default            # The default ca section
[ CA_default ]
dir             = .                      # Where everything is kept
certs           = \$dir/certs            # Where the issued certs are kept
crl_dir         = \$dir/crl              # Where the issued crl are kept
database        = \$dir/index.txt        # database index file.
                                         # several ctificates with same subject.
new_certs_dir   = \$dir/newcerts         # default place for new certs.
certificate     = \$dir/rootCA.crt       # The CA certificate
serial          = \$dir/serial           # The current serial number
crlnumber       = \$dir/crlnumber        # the current crl number
                                         # must be commented out to leave a V1 CRL
crl             = \$dir/crl.pem          # The current CRL
private_key     = \$dir/private/rootCA.key # The private key
RANDFILE        = \$dir/private/.rand    # private random number file
x509_extensions = usr_cert               # The extentions to add to the cert
name_opt        = ca_default             # Subject Name options
cert_opt        = ca_default             # Certificate field options
default_days    = 365                    # how long to certify for
default_crl_days= 30                     # how long before next CRL
default_md      = default                # use public key default MD
preserve        = no                     # keep passed DN ordering
policy          = policy_match
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ req ]
default_bits            = 
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert
string_mask = utf8only
[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $ENV::KEY_COUNTRY
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $ENV::KEY_PROVINCE
localityName                    = Locality Name (eg, city)
localityName_defailt            = $ENV::KEY_CITY
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $ENV::KEY_ORG
organizationalUnitName          = Organizational Unit Name (eg, section)
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_default            = $ENV::KEY_EMAIL
emailAddress_max                = 64
[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
[ crl_ext ]
authorityKeyIdentifier=keyid:always
[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
[ tsa ]
default_tsa = tsa_config1       # the default TSA section
[ tsa_config1 ]
dir             = ./demoCA              # TSA root directory
serial          = \$dir/tsaserial        # The current serial number (mandatory)
crypto_device   = builtin               # OpenSSL engine to use for signing
signer_cert     = \$dir/tsacert.pem      # The TSA signing certificate
                                        # (optional)
certs           = \$dir/rootCA.crt       # Certificate chain to include in reply
                                        # (optional)
signer_key      = \$dir/private/rootCA.key # The TSA private key (optional)
default_policy  = tsa_policy1           # Policy if request did not specify it
                                        # (optional)
other_policies  = tsa_policy2, tsa_policy3      # acceptable policies (optional)
digests         = md5, sha1             # Acceptable message digests (mandatory)
accuracy        = secs:1, millisecs:500, microsecs:100  # (optional)
clock_precision_digits  = 0     # number of digits after dot. (optional)
ordering                = yes   # Is ordering defined for timestamps?
                                # (optional, default: no)
tsa_name                = yes   # Must the TSA name be included in the reply?
                                # (optional, default: no)
ess_cert_id_chain       = no    # Must the ESS cert id chain be included?
                                # optional, default: no)
[ server ]
basicConstraints       = CA:FALSE
nsCertType             = server
nsComment              = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = serverAuth
keyUsage               = digitalSignature, keyEncipherment
EOF
}

OPENVPN_VERIFY() {
cat <<EOF
#!/bin/bash

genhash() {
        HASHPASS=\`echo -n "\$1\$2" | md5sum | sed s'/\  -//'\`
        i=0
        while [ \$i -lt 10 ]; do
                HASHPASS=\`echo -n \$HASHPASS\$HASHPASS | md5sum | sed s'/\  -//'\`
                i=\`expr \$i + 1\`
        done
        echo -n \$1:\$HASHPASS
}

verify() {
        USERS=\`cat ./versa/userpermissions\`
        
        [[ \$# -eq 2 ]] || exit 1
        [[ \$(sed -n "/^\$1\:/p" ./versa/userpermissions | cut -d':' -f 5) -eq 0 ]] && exit 1
        for i in \$USERS; do
                i=\$(echo "\$i" | sed -r 's/^([^\:]*:[0-9a-f]*):.*\$/\1/')
                [[ "\$i" == \`genhash "\$1" "\$2"\` ]] && exit 0
        done
}

[[ \$1 == "--genhash" ]] && echo \`genhash "\$2" "\$3"\`
[[ -e "\$*" ]] || exit 1
verify \`cat "\$*"\`
exit 1
EOF
}

EDIT_IT() {
cat <<EOF
#!/bin/bash
# Author: Rene Fa 2017

usage() { echo "Usage: \$0 instruction (instruction parameters) [options]

Global options:
    ( You have no options )

Instructions:
    switch filename bname bnumber [commentsign]
                        Activates only one block and comments the other blocks.
                        bname is the name of the block.
                        bnumber is the name of.
                        filename is the name of the file.
                        commentsign is the character, which initiates a comment.

    delete filename bname bnumber [commentsign]
                        Deletes a block.

    create filename bname bnumber [line-number] [commentsign]
                        Create a new block after the given line-number.

    clear filename bname bnumber [commentsign]
                        Empty the content of a block.

    enable filename bname bnumber [commentsign]
                        Uncomments a single block.

    disable filename bname bnumber [commentsign]
                        Comments a single block.

    get filename bname bnumber [commentsign]
                        Prints the content of the block uncommented.

    state filename bname [commentsign]
                        Prints the state of a block.

    insert filename bname bnumber new-line [line-number] [commentsign]
                        Appends a new line to a block.
                        A line-number of 0 means appending at the end of
                        the block. (default value)

    dell filename bname bnumber line-number [commentsign]
                        Deletes a specific line from a block.
"
}

if test \$# -lt 3
then
    echo "editIt: Too few arguments!"
    usage
    exit
fi
instr=\$1
case "\$instr" in
"state")
    filename=\$2
    block=\$3
    csign=\$4
;;
"insert")
    if test \$# -lt 5
    then
        echo "editIt: Too few arguments!"
        exit
    fi
    filename=\$2
    block=\$3
    state=\$4
    data=\$5

    if test \$# -gt 5; then
        data2=\$6
        csign=\$7
    else
        data2=0
        csign=""
    fi
;;
"dell")
    if test \$# -lt 5
    then
        echo "editIt: Too few arguments!"
        exit
    fi

    filename=\$2
    block=\$3
    state=\$4
    data=\$5
    csign=\$6
;;
"create")
    if test \$# -lt 4
    then
        echo "editIt: Too few arguments!"
        exit
    fi

    filename=\$2
    block=\$3
    state=\$4

    if test \$# -gt 4; then
        data=\$5
        csign=\$6
    else
        data=0
        csign=""
    fi
;;
*)
    if test \$# -lt 4
    then
        echo "editIt: Too few arguments!"
        exit
    fi

    filename=\$2
    block=\$3
    state=\$4
    csign=\$5
;;
esac

if test "\$csign" = ""
then
    csign="#"
fi

if test "\$instr" = "state"
then
    awk "/\$csign IFCBLOCK \$block /{print}" \$filename | awk '{print \$4" "\$5}'
elif test "\$instr" = "create"; then
    test "\$data" == "0" && data=\$(sed -n '\$=' \$filename)
    sed -i "\${data}a \${csign} IFCBLOCK \$block \$state 1" \$filename
    sed -i "\$(( \${data} +1 ))a \${csign} ENDIFCBLOCK \$block" \$filename
elif [[ \$instr =~ (switch|delete|clear|enable|disable|insert|get|dell) ]]
then
    snum=(\`sed -n "/^\$csign IFCBLOCK \$block /=" \$filename | tr '\n' ' '\`)
    enum=(\`sed -n "/^\$csign ENDIFCBLOCK \$block\$/=" \$filename | tr '\n' ' '\`)
    
    if test \${#snum[*]} -ne \${#enum[*]}
    then
        echo "editIt: Syntax Error!"
        exit
    fi
    count=\${#snum[*]}

    for (( i=0; i<\$count; i++ ))
    do
        sb=\$(( \${snum[\$i]} + 1 ))
        eb=\$(( \${enum[\$i]} - 1 ))
        empty=0
        test \$sb -gt \$eb && empty=1

        lstate=\$(sed -ne "\${snum[\$i]}p" \$filename | awk "/\$csign IFCBLOCK \$block /{print}" | awk '{print \$4}')

        case "\$instr" in
        "switch")
            if test \$state -eq \$lstate
            then
                bst=\$(sed -n "\${snum[\$i]}p" \$filename | cut -d' ' -f 5)
                test \$bst -eq 1 && continue
                test \$empty -eq 1 && continue
                sed -i -r -e "\${sb},\${eb}s/^\${csign}(.*)/\1/" \$filename
                sed -i -e "\${snum[\$i]}s/^.*\$/\${csign} IFCBLOCK \$block \$lstate 1/" \$filename
            else
                bst=\$(sed -n "\${snum[\$i]}p" \$filename | cut -d' ' -f 5)
                test \$bst -eq 0 && continue
                sed -i -e "\${sb},\${eb}s/^/\${csign}/" \$filename
                sed -i -e "\${snum[\$i]}s/^.*\$/\${csign} IFCBLOCK \$block \$lstate 0/" \$filename
            fi
            ;;
        "delete")
            if test \$state -eq \$lstate
            then
                sed -i -e "\${snum[\$i]},\${enum[\$i]}d" \$filename
                dsub=\$(( \${enum[\$i]} +1 -\${snum[\$i]} ))
                for (( j=\$i; j<\$count; j++ )) ; do
                    snum[\$j]=\$(( \${snum[\$j]} -\$dsub ))
                    enum[\$j]=\$(( \${enum[\$j]} -\$dsub ))
                done
            fi
            ;;
        "clear")
            if test \$state -eq \$lstate
            then
                test \$empty -eq 1 && continue
                sed -i -e "\${sb},\${eb}d" \$filename
                dsub=\$(( \${eb} +1 -\${sb} ))
                for (( j=\$i; j<\$count; j++ )) ; do
                    snum[\$j]=\$(( \${snum[\$j]} -\$dsub ))
                    enum[\$j]=\$(( \${enum[\$j]} -\$dsub ))
                done
            fi
            ;;
        "enable")
            if test \$state -eq \$lstate
            then
                bst=\$(sed -n "\${snum[\$i]}p" \$filename | cut -d' ' -f 5)
                test \$bst -eq 1 && continue
                test \$empty -eq 1 && continue
                sed -i -r -e "\${sb},\${eb}s/^\${csign}(.*)/\1/" \$filename
                sed -i -e "\${snum[\$i]}s/^.*\$/\${csign} IFCBLOCK \$block \$lstate 1/" \$filename
            fi
            ;;
        "disable")
            if test \$state -eq \$lstate
            then
                bst=\$(sed -n "\${snum[\$i]}p" \$filename | cut -d' ' -f 5)
                test \$bst -eq 0 && continue
                test \$empty -eq 1 && continue
                sed -i -e "\${sb},\${eb}s/^/\${csign}/" \$filename
                sed -i -e "\${snum[\$i]}s/^.*\$/\${csign} IFCBLOCK \$block \$lstate 0/" \$filename
            fi
            ;;
        "get")
            if test \$state -eq \$lstate
            then
                test \$empty -eq 1 && continue
                sed -n -e "\${sb},\${eb}s/^\${csign}*//p" \$filename
                exit 0
            fi
            ;;
        "insert")
            if test \$state -eq \$lstate
            then
                test \$data2 -eq 0 && tb=\$eb || tb=\$(( \${snum[\$i]} -1 +\$data2))
                bst=\$(sed -n "\${snum[\$i]}p" \$filename | cut -d' ' -f 5)
                sed -i "\${tb}a \$data" \$filename

                dsub=\$(echo "\$data" | sed 's/\\n/\n/g' | wc -l)
                if test \$bst -eq 0; then
                    for (( j=0; j<\$dsub; j++ )) ; do
                        sed -i "\$(( \${tb} +1 +\$j ))s/^/\${csign}/" \$filename
                    done
                fi

                for (( j=\$i; j<\$count; j++ )) ; do
                    snum[\$j]=\$(( \${snum[\$j]} +\$dsub ))
                    enum[\$j]=\$(( \${enum[\$j]} +\$dsub ))
                done
            fi
            ;;
        "dell")
            if test \$state -eq \$lstate
            then
                ln=\$(( \${snum[\$i]} +\$data ))
            
                if test \$ln -lt \$sb -o \$ln -gt \$eb; then
                    echo "editIt: Index out of bounds"
                    exit 1
                fi

                sed -i "\${ln}d" \$filename
                dsub=1
                for (( j=\$i; j<\$count; j++ )) ; do
                    snum[\$j]=\$(( \${snum[\$j]} -\$dsub ))
                    enum[\$j]=\$(( \${enum[\$j]} -\$dsub ))
                done
            fi
            ;;
        esac
    done
fi
EOF
}

VERSA_AUTOCOMPLETE() {
cat <<EOF
_versa_getuser() {
    COMPREPLY=(\$( compgen -W "\$(cat $OPENVPN_PATH/versa/userpermissions | cut -d':' -f 1)" -- \$cur))
}

_versa_getgroup() {
    COMPREPLY=(\$( compgen -W "\$(cat $OPENVPN_PATH/versa/groups)" -- \$cur))
}

_versa_gettargetgroup() {
    COMPREPLY=(\$( compgen -W "\$(cat $OPENVPN_PATH/versa/targetgroups)" -- \$cur))
}

_versa ()
{
  local cur

  COMPREPLY=( )
  cur=\${COMP_WORDS[COMP_CWORD]}
    
    case "\$COMP_CWORD" in
    1)
        COMPREPLY=(\$( compgen -W 'install useradd userdel usermod certrefresh certexport userlist userinfo rebuild clean useraccessadd useraccessdel usertargetadd usertargetdel userenable userdisable vlanlist vlaninfo' -- \$cur ) )
        ;;
    2)
        case "\${COMP_WORDS[1]}" in
            userdel) _versa_getuser ;;
            usermod) _versa_getuser ;;
            certrefresh) _versa_getuser ;;
            certexport) _versa_getuser ;;
            userinfo) _versa_getuser ;;
            useraccessadd) _versa_getuser ;;
            useraccessdel) _versa_getuser ;;
            usertargetadd) _versa_getuser ;;
            userenable) _versa_getuser ;;
            userdisable) _versa_getuser ;;
            vlaninfo) _versa_getgroup ;;
        esac
        ;;
    3)
        case "\${COMP_WORDS[1]}" in
            useraccessadd) _versa_getgroup ;;
            useraccessdel) _versa_getgroup ;;
            usertargetadd) _versa_gettargetgroup ;;
            usertargetdel) _versa_gettargetgroup ;;
        esac
        ;;
    esac

  return 0
}

complete -F _versa -o filenames versa
EOF
}

##################################################################################
##################################################################################
##################################################################################

usage() { echo "Usage: $0 instruction (instruction parameters) [options]

Global options:
       -q               Quick and Quiet Mode. Just fill in the standard parameters and
                        dont ask any questions. Just ask for password if needed.

       -d               Debug mode. Forwards the stdout of used programs.
                        Prints much more information.

       -c filename      Change the output directory for the zip Package with the
                        certificates and config.
                        The default output is defined in the first lines of this script.
                        The password of the file is the new password of the user.

        -m              Multiple files flag. With this mode enabled, the certicatates
                        are seperated in own files. Default is defined in config.

        -s              Single file flag. Store all certificated in a single file.
                        The default setting is defined in the config.

Instructions:
    install
                        Backup the old configuration and install versa.

    useradd username [options]
                        Adds the specified user to the userlist, generate the
                        certificats and stores them in a given directory.

        -p string       Set a new password, to avoid the interactive prompt.
                        AVOID USING THIS PARAMETER FOR SECURITY REASONS!

        -v stringrule   Define the VLAN access rules.
                        Example: \"t=gaming,private;a=gaming,private,gateway\"
                        You are in the group gaming and private that means all
                        clients with the gaming and private permission can reach
                        your machine. The access rule are the networks that you can
                        reach.

        -a ip-address   Preselect a custom IP-address. With the -q option,
                        the prompt will be omited.

    userdel username [options]
                        Removes a user from the userlist and adds the certificates
                        to the blacklist.

    usermod username [options]
                        Change properties of a user.

        -p string       Set a new password, to avoid the interactive prompt.
                        AVOID USING THIS PARAMETER FOR SECURITY REASONS!

        -a ip-address   Preselect a custom IP-address. With the -q option,
                        the prompt will be omited.

    certrefresh username [options]
                        Creates new certificates and revoke the old ones.

    certexport username [options]
                        Export the certificates to a specified directory.

    userlist [options]
                        List all users.

    userinfo username [options]
                        Gives detailed information about a user.

    userenable username [options]
                        Activates a VPN user.

    userdisable username [options]
                        Deactivates a VPN user.

    rebuild [options]
                        Rebuild all Firewall rules and DNS rules. Must be called
                        after every change in the VLAN/DNS config section.

    clean [options]
                        Revert all changes which are made by versa.
                        Including /etc/hosts, iptables rules

    useraccessadd username vlanname [options]
                        Grant the access to a group

    useraccessdel username vlanname [options]
                        Revokes the access to a group.

    usertargetadd username vlanname [options]
                        Add a user to a group target list. Every user with the
                        access permision can reach this client.

    usertargetdel username vlanname [options]
                        Removes a user from a group target list.

    vlanlist [options]
                        List all current VPN VLANs.

        -u              Just list the VPN VLANs without more information.

    vlaninfo vlanname [options]
                        Gives detailed information about a VPN VLAN.
"
exit 1
}

vkilled() {
    stty echo
    echo -en "\033[0m"

    [[ $(jobs -p | wc -l) -gt 0 ]] && kill $(jobs -p)
}

tmpc=0
for (( i=0; i<4; i++ ))
do
    oct=$(echo $SUBNET_MASK | cut -d'.' -f $(( $i +1 )))

    [[ "$oct" = "255" ]] && tmpc=$(( $tmpc +8 ))
    [[ "$oct" = "0" ]] && break
    [[ "$oct" = "128" ]] && tmpc=$(($tmpc +1)) && break
    [[ "$oct" = "192" ]] && tmpc=$(($tmpc +2)) && break
    [[ "$oct" = "224" ]] && tmpc=$(($tmpc +3)) && break
    [[ "$oct" = "240" ]] && tmpc=$(($tmpc +4)) && break
    [[ "$oct" = "248" ]] && tmpc=$(($tmpc +5)) && break
    [[ "$oct" = "252" ]] && tmpc=$(($tmpc +6)) && break
    [[ "$oct" = "254" ]] && tmpc=$(($tmpc +7)) && break
done
SUBNET_CIDR="$SUBNET_IP/$tmpc"

iptoraw() {
    let "rawip= $(echo $1 | cut -d'.' -f 4) +$(echo $1 | cut -d'.' -f 3)*256 +$(echo $1 | cut -d'.' -f 2)*256*256 +$(echo $1 | cut -d'.' -f 1)*256*256*256"
    echo -n "$rawip"
}

iptoform() {
    r=$1

    let "o1 = $r % 256"
    let "r = $r / 256"

    let "o2 = $r % 256"
    let "r = $r / 256"

    let "o3 = $r % 256"
    let "r = $r / 256"

    let "o4 = $r % 256"

    echo -n "$o4.$o3.$o2.$o1"
}

IP_OFFSET=$(( $(iptoraw $(echo "$USER_IP_RANGE" | cut -d'-' -f 1)) -$(iptoraw $(echo "$SUBNET_IP" | cut -d'-' -f 1)) -1 ))
MIN_IP="$(iptoraw $(echo -n "$USER_IP_RANGE" | cut -d'-' -f 1))"
MAX_IP="$(iptoraw $(echo -n "$USER_IP_RANGE" | cut -d'-' -f 2))"

AMIN_IP="$(( $(iptoraw $SUBNET_IP) +2 ))"
AMAX_IP="$(( ( $(iptoraw $SUBNET_IP) | ( 4294967295 & ~$(iptoraw $SUBNET_MASK) ) ) -1 ))"

SERVER_IP="$(iptoform $(( $(iptoraw $SUBNET_IP) +1 )))"



checkip() {
    FIP=$(iptoraw $1)

    [[ $(( $FIP -$AMIN_IP )) -lt 0 ]] && return 1
    [[ $(( $AMAX_IP -$FIP )) -lt 0 ]] && return 1
    
    for i in $(ls /etc/openvpn/ccd/)
    do
        [[ "$1" = "$(cat /etc/openvpn/ccd/$i | head -n 1 | cut -d' ' -f 2)" ]] && return 1
    done

    return 0
}

searchip() {
    
    for (( i=0;i<$(( $MAX_IP -$MIN_IP ));i++ ))
    do
        found=1
        tip=$(iptoform $(( $MIN_IP+$i )))
        for j in $(ls /etc/openvpn/ccd/)
        do
            [[ "$tip" = "$(cat /etc/openvpn/ccd/$j | head -n 1 | cut -d' ' -f 2)" ]] && found=0 && break
        done

        [[ $found -eq 1 ]] && echo "$tip" && return 0
    done

    return 1
}

verboselog() {

    trap '[[ $(ps $rcid | wc -l) -gt 1 ]] && kill $rcid' EXIT
    while : ;
    do
        if test $d -eq 1
        then
            cat $FP &
            rcid=$!
            wait $rcid
        else
            cat $FP > /dev/null &
            rcid=$!
            wait $rcid
        fi
    done
}

VLAN_EXIST() {
    VEOPWD="$(pwd)"
    cd $OPENVPN_PATH/versa

    for (( j=0; j<${#GROUP_NAME[*]}; j++ ))
    do
        [[ "${GROUP_NAME[$j]}" = "$1" ]] && cd $VEOPWD && return 0
    done

    cd $VEOPWD
    return 1
}

VLAN_T_EXIST() {
    VEOPWD="$(pwd)"
    cd $OPENVPN_PATH/versa

    for (( j=0; j<${#GROUP_NAME[*]}; j++ ))
    do
        [[ "${GROUP_NAME[$j]}" = "$1" ]] && [[ -n "$(echo "${GROUP_VLAN_RULE[$j]}" | sed -n '/TARGET/p')" ]] && cd $VEOPWD && return 0
    done

    cd $VEOPWD
    return 1
}

USER_EXIST() {
    OPWD="$(pwd)"
    cd $OPENVPN_PATH/versa
    
    for i in $(cat userpermissions | cut -d':' -f 1 | tr '\n' ' ')
    do
        if test "$1" = "$i"
        then
            return 0
        fi
    done
    return 1
    cd $OPWD
}

vlan_user_add() {
    OPWD="$(pwd)"
    cd $OPENVPN_PATH/versa

    userstr=$(cat userpermissions | sed -n "/^$1:/p")
    tname=$(echo "$userstr" | cut -d':' -f 1)
    U_IP="$(cat ../ccd/$tname | head -n 1 | cut -d' ' -f 2)"

    lista=(`echo "$userstr" | cut -d':' -f 3 | tr ',' ' '`)
    for (( i=0; i<${#lista[*]}; i++ ))
    do
        cag="${lista[$i]}"
        
        if !(VLAN_EXIST $cag); then
                echo -e "\033[31mGroup $cag not found!\033[0m"
                return 1
        fi
        
        count=${#GROUP_NAME[*]}
        for (( j=0; j<$count; j++ ))
        do
                [[ "${GROUP_NAME[$j]}" = "$cag" ]] && gn=$j
        done
        
        if test -n "${GROUP_SERVER_RULE[$gn]}"; then
            IFS=";"
            for rule in ${GROUP_SERVER_RULE[$gn]}; do
                eval $(echo "iptables -A v-${GROUP_NAME[$gn]}-s -s $U_IP $rule")
            done
            unset IFS
            
            iptables -A v-${GROUP_NAME[$gn]}-s -j RETURN
            iptables -D v-${GROUP_NAME[$gn]}-s -j RETURN
        fi
        
        if test -n "${GROUP_VLAN_RULE[$gn]}"; then
            IFS=";"
            for rule in ${GROUP_VLAN_RULE[$gn]}; do
                eval $(echo "iptables -A v-${GROUP_NAME[$gn]}-a -s $U_IP $rule" | sed "s/TARGET/v\-${GROUP_NAME[$gn]}\-t/")
            done
            unset IFS
            
            iptables -A v-${GROUP_NAME[$gn]}-a -j RETURN
            iptables -D v-${GROUP_NAME[$gn]}-a -j RETURN
        fi
        
        # Conf rules
        if test -n "${GROUP_CONF_RULE[$gn]}"; then
            IFS=";"
            for rule in ${GROUP_CONF_RULE[$gn]}; do
                ./editIt.sh insert ../ccd/$1 VERSA_CONF 0 "$rule"
            done
            unset IFS
        fi
        
        # Custom rules
        if test -n "${GROUP_CUSTOM_ADD_USER[$gn]}"; then
            eval $(echo "${GROUP_CUSTOM_ADD_USER[$gn]}" | sed "s/U_IP/$U_IP/" | sed "s/U_NAME/$1/")
        fi
    done
    
    listt=(`echo "$userstr" | cut -d':' -f 4 | tr ',' ' '`)
    for (( i=0; i<${#listt[*]}; i++ ))
    do
    
        ctg="${listt[$i]}"
        $(echo "iptables -A v-$ctg-t" -d $U_IP -j ACCEPT)
        
        iptables -A v-$ctg-t -j RETURN
        iptables -D v-$ctg-t -j RETURN
        
    done 
    
    ./editIt.sh insert /etc/hosts VERSA_DNS 0 "$U_IP ${1}${DNS_LONG_PREFIX} ${1}${DNS_SHORT_PREFIX}"
    
    cd $OPWD
}

versa_clean() {
    OPWD="$(pwd)"
    cd $OPENVPN_PATH/versa
    
    ./editIt.sh clear /etc/hosts VERSA_DNS 0
    systemctl restart dnsmasq

    # Base Rule
    iptables -t nat -D POSTROUTING -s $SUBNET_CIDR -o $GATEWAY_INTERFACE -j MASQUERADE 2>/dev/null

    # Delete Chains
    iptables -D FORWARD -s $SUBNET_CIDR -j versa-vlan 2>/dev/null
    iptables -D FORWARD -d $SUBNET_CIDR -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    #iptables -D FORWARD -s $SUBNET_CIDR -j DROP 2>/dev/null

    iptables -D INPUT -s $SUBNET_CIDR -j versa-server 2>/dev/null
    #iptables -D INPUT -s $SUBNET_CIDR -j DROP 2>/dev/null

    iptables -F versa-vlan 2>/dev/null
    iptables -X versa-vlan 2>/dev/null
    
    iptables -F versa-server 2>/dev/null
    iptables -X versa-server 2>/dev/null

    ochains=(`iptables -nL | sed -nr 's/^Chain (v\-[A-Za-z0-9\_]*\-a) .*$/\1/p' | tr '\n' ' '`)
    count=${#ochains[*]}
    for (( i=0; i<$count; i++ ))
    do
        ch="${ochains[$i]}"
        iptables -F $ch
        iptables -X $ch
    done

    ochains=(`iptables -nL | sed -nr 's/^Chain (v\-[A-Za-z0-9\_]*\-t) .*$/\1/p' | tr '\n' ' '`)
    count=${#ochains[*]}
    for (( i=0; i<$count; i++ ))
    do
        ch="${ochains[$i]}"
        iptables -F $ch
        iptables -X $ch
    done
    
    ochains=(`iptables -nL | sed -nr 's/^Chain (v\-[A-Za-z0-9\_]+\-s) .*$/\1/p' | tr '\n' ' '`)
    count=${#ochains[*]}
    for (( i=0; i<$count; i++ ))
    do
        ch="${ochains[$i]}"
        iptables -F $ch
        iptables -X $ch
    done
    
    # Delete conf rules
    if [ -n "$(ls -A ../ccd)" ]; then
            for filename in ../ccd/*; do
                ./editIt.sh clear $filename VERSA_CONF 0
            done
    fi
    
    # Delete custom rules
    count=${#GROUP_NAME[*]}
    for (( i=0; i<$count; i++ ))
    do
            [[ -n ${GROUP_CUSTOM_CLEAN[$i]} ]] && eval ${GROUP_CUSTOM_CLEAN[$i]}
            [[ -n ${GROUP_CUSTOM_FINALIZE[$i]} ]] && eval ${GROUP_CUSTOM_FINALIZE[$i]}
    done
    
    cd $OPWD
}

versa_build() {

    [[ $GROUPS_ENABLED -eq 0 ]] && echo -e "\033[31mGroupsystem deactivated.\033[0m" && return 1

    OPWD="$(pwd)"
    cd $OPENVPN_PATH/versa
    
    iptables -t nat -A POSTROUTING -s $SUBNET_CIDR -o $GATEWAY_INTERFACE -j MASQUERADE

    iptables -N versa-vlan
    iptables -N versa-server
    
    iptables -A FORWARD -s $SUBNET_CIDR -j versa-vlan
    iptables -A FORWARD -d $SUBNET_CIDR -m state --state ESTABLISHED,RELATED -j ACCEPT
    #iptables -A FORWARD -s $SUBNET_CIDR -j DROP

    iptables -A INPUT -s $SUBNET_CIDR -j versa-server
    #iptables -A INPUT -s $SUBNET_CIDR -j DROP

    iptables -A versa-vlan -m state --state ESTABLISHED,RELATED -j ACCEPT 
    iptables -A versa-vlan -j RETURN
    
    iptables -A versa-server -m state --state ESTABLISHED,RELATED -j ACCEPT 
    iptables -A versa-server -j RETURN
    
    count=${#GROUP_NAME[*]}
    for (( i=0; i<$count; i++ ))
    do
        cn="${GROUP_NAME[$i]}"
        csr="${GROUP_SERVER_RULE[$i]}"
        cvr="${GROUP_VLAN_RULE[$i]}"
        
        if test -n "$csr"
        then
            iptables -N v-$cn-s
            iptables -A v-$cn-s -j RETURN

            iptables -A versa-server -j v-$cn-s
            iptables -A versa-server -j RETURN
            iptables -D versa-server -j RETURN
        fi

        if test -n "$cvr"
        then
                    iptables -N v-$cn-a
                    iptables -A v-$cn-a -j RETURN

                    iptables -A versa-vlan -j v-$cn-a
                    iptables -A versa-vlan -j RETURN
                    iptables -D versa-vlan -j RETURN
                    
                    if test -n "$(echo "$cvr" | sed -n '/TARGET/p')"
                    then
                            iptables -N v-$cn-t
                            iptables -A v-$cn-t -j RETURN
                    fi
                fi
    done

    count=${#GROUP_NAME[*]}
    for (( i=0; i<$count; i++ ))
    do
            [[ -n ${GROUP_CUSTOM_INIT[$i]} ]] && eval ${GROUP_CUSTOM_INIT[$i]}
    done
    
    for i in $(cat userpermissions | cut -d':' -f 1)
    do
        vlan_user_add $i
    done
    
    systemctl restart dnsmasq
    systemctl restart openvpn
    
    count=${#GROUP_NAME[*]}
    for (( i=0; i<$count; i++ ))
    do
            [[ -n ${GROUP_CUSTOM_FINALIZE[$i]} ]] && eval ${GROUP_CUSTOM_FINALIZE[$i]}
    done
    
    # Only important for autocomplete
    IFS="
    "
    echo -n "${GROUP_NAME[*]}" > groups

    echo -n "" > targetgroups
    for i in ${!GROUP_NAME[*]}; do
        [[ -n "$(echo "${GROUP_VLAN_RULE[$i]}" | sed -n '/TARGET/p')" ]] && echo "${GROUP_NAME[$i]}" >> targetgroups
    done

    unset IFS
    
    cd $OPWD
}

GET_USERDATA() {

    pstr="$(sed -n "/^$1\:/p" userpermissions)"
    p1="$(echo "$pstr" | cut -d':' -f 1)"
    p2="$(echo "$pstr" | cut -d':' -f 2)"
    p3="$(echo "$pstr" | cut -d':' -f 3)"
    p4="$(echo "$pstr" | cut -d':' -f 4)"
    p5="$(echo "$pstr" | cut -d':' -f 5)"
}

SET_USERDATA() {

    pl=$(sed -n "/^$p1:/=" userpermissions)
    
    p1=$1
    p2=$2
    p3=$3
    p4=$4
    p5=$5
    
    sed -rie "${pl}c\\$p1:$p2:$p3:$p4:$p5" userpermissions
}

trap 'vkilled' EXIT

if test $# -eq 0; then
    usage
    exit 1
fi

# Set the Mode
mode="$1"

# Extract the name
if [[ $1 =~ (useradd|userdel|usermod|certrefresh|certexport|userinfo|userenable|userdisable|vlaninfo|test) ]]
then
    if test $# -eq 1; then
        echo -e "\033[31mError: Too few arguments.\033[0m"
        usage
        exit 1;
    fi
    name=$2
    shift 1
elif [[ $1 =~ (useraccessadd|useraccessdel|usertargetadd|usertargetdel) ]]
then
    if test $# -lt 3; then
        echo -e "\033[31mError: Too few arguments.\033[0m"
        usage
        exit 1;
    fi
    name=$2
    name2=$3
    shift 2
fi
shift 1

#echo "$*"

p=""
v=""
c="$ZIP_DESTINATION"
a=""
u=0
q=0
d=0


# Get parameters
while getopts ":p:v:c:a:qdsm" o; do
    case "${o}" in
        p)
            p=${OPTARG}
            ;;
        v)
            v=${OPTARG}

            IFS=";"
            for i in $v
            do
                on=$(echo "$i" | sed -nr 's/^(.*)\=.*$/\1/p')
                od=$(echo "$i" | sed -nr 's/^.*\=(.*)$/\1/p')

                if test "$on" = "a"
                then
                    IFS=","
                    for j in $od; do
                        if !(VLAN_EXIST $j); then
                            echo -e "\033[31mNot existing Access group found in stringrule!\033[0m"
                            exit 1
                        fi
                    done
                    IFS=";"
                elif test "$on" = "t"
                then
                    IFS=","
                    for j in $od; do
                        if !(VLAN_T_EXIST $j); then
                            echo -e "\033[31mNot existing Target group found in stringrule!\033[0m"
                            exit 1
                        fi
                    done
                    IFS=";"
                fi
            done
            unset IFS
            ;;
        c)
            c=${OPTARG}
            ;;
        a)
            a=${OPTARG}
            if !(checkip $a)
            then
                echo -e "\033[31mInvalid IP-address or already used.\033[0m"
                exit 1
            fi
            ;;
        d)
            d=1
            ;;
        q)
            q=1
            d=0
            ;;
        s)
            SINGLE_CERT=1
            ;;
        m)
            SINGLE_CERT=0
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if !(test -e "$FP")
then
    mkfifo $FP
fi

[[ $DEBUG -eq  1 ]] && d=1

verboselog &
cid=$!

case "$mode" in
"install")
    ODIR="$(readlink -f $0)"
    [[ $q -eq 0 ]] && echo -e "\e[1;92mInstalling versa...\e[0m"

    [[ $q -eq 0 ]] && echo -e "\e[92mInstalling openvpn...\e[0m"
    apt-get update >$FP
    apt-get install openvpn dnsmasq zip iptables -y >$FP

    if test -d /etc/openvpn.bak/
    then
        echo -en "\033[31mOld Backup found! Replace? [y/N]: \033[0m"
        read entry
        if [[ "$entry" = "y" ]]; then
            [[ $q -eq 0 ]] && echo -e "\e[92mBackup old configuration...\e[0m"
            systemctl stop openvpn
            rm -r /etc/openvpn.bak
            mv $OPENVPN_PATH /etc/openvpn.bak
        else
            systemctl stop openvpn
            rm -r /etc/openvpn
        fi
    else
        mv $OPENVPN_PATH /etc/openvpn.bak
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mDeploy new openssl configuration...\e[0m"
    
    mkdir -p $OPENVPN_PATH/versa/users/.deleted
    mkdir -p $OPENVPN_PATH/versa/newcerts
    mkdir -p $OPENVPN_PATH/versa/certs
    
    chmod -R 755 $OPENVPN_PATH
    chmod -R 755 $OPENVPN_PATH/versa
    chmod -R 700 $OPENVPN_PATH/versa/users
    
    echo "01" > $OPENVPN_PATH/versa/serial
    echo "01" > $OPENVPN_PATH/versa/crlnumber

    cd $OPENVPN_PATH/versa
    touch index.txt
    touch index.txt.attr

    echo "$(OPENSSL_CONF)" | cat > openssl.cnf
    
    [[ $q -eq 0 ]] && echo -e "\e[92mInstalling scripts...\e[0m"
    echo "$(EDIT_IT)" | cat > editIt.sh
    chmod 750 editIt.sh
    mkdir ../ccd
    
    [[ $q -eq 0 ]] && echo -e "\e[92mGenerate DH Parameters (can take a long time)...\e[0m"
    openssl dhparam -out dh.pem $KEY_SIZE 2>$FP

    [[ $q -eq 0 ]] && echo -e "\e[92mGenerate CA Key...\e[0m"
    openssl genrsa -out rootCA.key $KEY_SIZE 2>$FP

    [[ $q -eq 0 ]] && echo -e "\e[92mCreate CA Cert...\e[0m"
    openssl req -x509 -new -nodes -config openssl.cnf -key rootCA.key -sha256 -days $CA_EXPIRE -out rootCA.crt -subj "/C=$KEY_COUNTRY/ST=$KEY_PROVINCE/L=$KEY_CITY/O=$KEY_ORG/OU=$KEY_OU/CN=rootCA"

    [[ $q -eq 0 ]] && echo -e "\e[92mCreate Server Cert and Key...\e[0m"
    openssl genrsa -out server.key $KEY_SIZE 2>$FP

    openssl req -nodes -new -config openssl.cnf -extensions server -key server.key -out server.csr -subj "/C=$KEY_COUNTRY/ST=$KEY_PROVINCE/L=$KEY_CITY/O=$KEY_ORG/OU=$KEY_OU/CN=server"
    yes | openssl ca -config openssl.cnf -extensions server -keyfile rootCA.key -cert rootCA.crt -out server.crt -in server.csr -days $CA_EXPIRE -md sha256 2>$FP
    
    chmod 600 server.key
    chmod 600 rootCA.key
    chown nobody:nogroup server.key
    chown nobody:nogroup rootCA.key

    [[ $q -eq 0 ]] && echo -e "\e[92mCreate certificate revocation list...\e[0m"
    openssl ca -config openssl.cnf -gencrl -crldays $CA_EXPIRE -keyfile rootCA.key -cert rootCA.crt -out crl.pem 2>$FP
    chown nobody:nogroup crl.pem
    
    [[ $q -eq 0 ]] && echo -e "\e[92mObtain public IP-Address...\e[0m"
    PUBLIC_IP=$(wget -q -O - checkip.dyndns.org|sed -e 's/.*Current IP Address: //' -e 's/<.*$//')
    [[ $q -eq 0 ]] && echo "Public IP-address: $PUBLIC_IP"
    echo "$PUBLIC_IP" > publicip

    [[ $q -eq 0 ]] && echo -e "\e[92mConfigure DNS Server...\e[0m"
    
    ./editIt.sh delete /etc/hosts VERSA_DNS 0
    ./editIt.sh create /etc/hosts VERSA_DNS 0
    
    touch userpermissions

    [[ $q -eq 0 ]] && echo -e "\e[92mCreating tun0 interface\e[0m"
    if test -e /dev/net/tun; then
        modprobe tun
        mknod /dev/net/tun c 10 200
        chown root:root /dev/net/tun
        chmod 600 /dev/net/tun
    fi

    #openvpn --mktun --dev tun0
    #ip link set tun0 up

    [[ $q -eq 0 ]] && echo -e "\e[92mSetting up Firewall\e[0m"
    versa_clean
    versa_build

    [[ $q -eq 0 ]] && echo -e "\e[92mSetting up configurations...\e[0m"
    echo "$(OPENVPN_CONF)" | cat > ../server.conf
    echo "$(OPENVPN_VERIFY)" | cat > verify.sh
    chown nobody:nogroup verify.sh
    chmod 755 verify.sh
    
    [[ $q -eq 0 ]] && echo -e "\e[92mStart openvpn...\e[0m"
    systemctl restart openvpn@server

    [[ $q -eq 0 ]] && echo -e "\e[92mFinalizing installation...\e[0m"
    sleep 1
    sysctl -w net.ipv4.ip_forward=1 >$FP
    sysctl -w net.ipv4.conf.all.send_redirects=0 >$FP
    sysctl -w net.ipv4.conf.tun0.send_redirects=0 >$FP
    
    ./editIt.sh delete /etc/sysctl.conf VERSA_REDIRECT 0
    ./editIt.sh create /etc/sysctl.conf VERSA_REDIRECT 0
    ./editIt.sh insert /etc/sysctl.conf VERSA_REDIRECT 0 "net.ipv4.ip_forward=1"
    ./editIt.sh insert /etc/sysctl.conf VERSA_REDIRECT 0 "net.ipv4.conf.all.send_redirects=0"
    ./editIt.sh insert /etc/sysctl.conf VERSA_REDIRECT 0 "net.ipv4.conf.tun0.send_redirects=0"

    rm /usr/bin/versa 2> /dev/null
    cp -f $ODIR /usr/bin/versa
    echo "$(VERSA_AUTOCOMPLETE)" > /etc/bash_completion.d/versa
    source /etc/bash_completion.d/versa

    ;;
"useradd")
    cd $OPENVPN_PATH/versa

    if USER_EXIST $name
    then
        echo -e "\033[31mUsername already exist! Choose another name.\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mAdding new user $name...\e[0m"
    if test "$p" = ""; then
        while : ; do
            [[ $q -eq 0 ]] && echo "Please enter a new password for the user."
            stty -echo
            echo -en "\033[33m"
            read -p "Password: " p; echo
            read -p "Repeat Password: " pc; echo
            echo -en "\033[0m"
            stty echo
            [[ "$p" == "$pc" ]] && break
            echo -e "\033[31mPassword not matching. Repeat.\033[0m"
        done
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mGenerating certificate...\e[0m"
    
    [ -d users/$name ] || mkdir users/$name
    
        openssl genrsa -out users/$name/client.key $KEY_SIZE 2>$FP
        openssl req -new -config openssl.cnf -key users/$name/client.key -out users/$name/client.csr -subj "/C=$KEY_COUNTRY/ST=$KEY_PROVINCE/L=$KEY_CITY/O=$KEY_ORG/OU=$KEY_OU/CN=$name"
        yes | openssl ca -config openssl.cnf -keyfile rootCA.key -cert rootCA.crt -out users/$name/client.crt -in users/$name/client.csr -days $KEY_EXPIRE -md sha256 2>$FP

    [[ "$a" != "" ]] && USER_IP="$a" || USER_IP=$(searchip)
    if test $q -eq 0
    then
        while : ; do
            [[ $q -eq 0 ]] && echo "Enter a custom IP address."
            [[ $q -eq 0 ]] && echo "Leave blank to use the default Value."

            echo -en "\033[33m"
            read -p "IP Address [$USER_IP]: " tUSER_IP;
            echo -en "\033[0m"
            test "$tUSER_IP" = "" && break
            checkip $tUSER_IP && USER_IP=$tUSER_IP && break
            echo -e "\033[31mInvalid IP address or already used. Repeat.\033[0m"
        done
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mSetting static IP...\e[0m"
    echo "ifconfig-push $USER_IP $SUBNET_MASK" > ../ccd/$name
    
    ./editIt.sh create ../ccd/$name VERSA_CONF 0
    
    if test -n "$v"
    then
        IFS=";"
        for i in $v
        do
            on=$(echo "$i" | sed -nr 's/^(.*)\=.*$/\1/p')
            od=$(echo "$i" | sed -nr 's/^.*\=(.*)$/\1/p')

            if test "$on" = "a"
            then
                STRR_A="$od"
            elif test "$on" = "t"
            then
                STRR_T="$od"
            fi
        done
        unset IFS
    else
        while : ; do
            [[ $q -eq 0 ]] && echo "Define the Access Groups in a comma seperated list"
            [[ $q -eq 0 ]] && echo "Example: gateway,admin,gaming"
            if [[ $q -eq 0 ]]; then
                echo -en "Available groups are: \033[1m"
                for i in ${!GROUP_NAME[@]}; do
                    echo -n "${GROUP_NAME[$i]} "
                done
                echo -e "\033[21m"
            fi

            echo -en "\033[33m"
            read -p "VLAN access rules: " STRR_At;
            echo -en "\033[0m"

            ERROR=0
            IFS=","
            for i in $STRR_At; do
                VLAN_EXIST $i || ERROR=1
            done
            unset IFS
            test $ERROR -eq 0 && STRR_A=$STRR_At && break
            echo -e "\033[31mInvalid groups. Repeat.\033[0m"
        done
        
        while : ; do
            [[ $q -eq 0 ]] && echo "Define the Target Groups in a comma seperated list"
            [[ $q -eq 0 ]] && echo "Example: gaming,private,servers"
            if [[ $q -eq 0 ]]; then
                echo -en "Available groups are: \033[1m"
                for i in ${!GROUP_NAME[@]}; do
                    [[ -z "$(echo "${GROUP_VLAN_RULE[$i]}" | sed -n '/ TARGET/p')" ]] && continue
                    echo -n "${GROUP_NAME[$i]} "
                done
                echo -e "\033[21m"
            fi

            echo -en "\033[33m"
            read -p "VLAN target rules: " STRR_Tt;
            echo -en "\033[0m"

            ERROR=0
            IFS=","
            for i in $STRR_Tt; do
                VLAN_T_EXIST $i || ERROR=1
            done
            unset IFS
            test $ERROR -eq 0 && STRR_T=$STRR_Tt && break
            echo -e "\033[31mInvalid groups. Repeat.\033[0m"
        done
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mAdding to user DB...\e[0m"
    echo "$(./verify.sh --genhash "$name" "$p"):$STRR_A:$STRR_T:1" >> userpermissions

    if [[ $GROUPS_ENABLED -eq 1 ]]; then
        [[ $q -eq 0 ]] && echo -e "\e[92mAdding new VLAN Rules...\e[0m"
        vlan_user_add $name
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mExporting certificates to: $c/$name.zip\e[0m"
    cd users/$name
    
    cp ../../rootCA.crt rootCA.crt
    echo "$(OPENVPN_CLIENT_CONF)" > client.ovpn
    echo "ca rootCA.crt" >> client.ovpn
    echo "cert client.crt" >> client.ovpn
    echo "key client.key" >> client.ovpn

    echo "$(OPENVPN_CLIENT_CONF)" > $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<ca>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat rootCA.crt >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</ca>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<cert>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat client.crt >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</cert>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<key>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat client.key >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</key>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn

    echo -en "${name}\n${p}" > authfile

    if [ $SINGLE_CERT -eq 0 ]
    then
        zip --password "$p" "$c/$name@$SERVER_NAME.$DOMAIN_NAME.zip" client.ovpn rootCA.crt client.crt client.key authfile >$FP
    else
        zip --password "$p" "$c/$name@$SERVER_NAME.$DOMAIN_NAME.zip" $name@$SERVER_NAME.$DOMAIN_NAME.ovpn authfile >$FP
    fi
    cd ../..

    ;;
"userdel")
    cd $OPENVPN_PATH/versa
    
    if !(USER_EXIST $name)
    then
        echo -e "\033[31mUsername not found!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mRemoving $name...\e[0m"
    cd $OPENVPN_PATH/versa
    [[ $q -eq 0 ]] && echo -e "\e[92mAdding user to the revocation list...\e[0m"
    openssl ca -config openssl.cnf -keyfile rootCA.key -cert rootCA.crt -revoke users/$name/client.crt 2>$FP

    [[ $q -eq 0 ]] && echo -e "\e[92mRemove configs...\e[0m"
    rm ../ccd/$name
    sed -i "/^$name\:/d" userpermissions
    
    [[ $q -eq 0 ]] && echo -e "\e[92mRemove certificates from userlist\e[0m"
    mv "users/$name" "users/.deleted/${name}_$(date +"%Y-%m-%d_%k-%M-%S")"

    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build

    ;;
"usermod")
    #pw,stringrule,ip
    cd $OPENVPN_PATH/versa
    
    if !(USER_EXIST $name)
    then
        echo -e "\033[31mUsername not found!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mModificate user $name...\e[0m"

    if test "$p" = "" -a $q -eq 0; then
        echo -en "\033[33mChange password? [y/N]: \033[0m"
        read entry
        if [ "$entry" = "y" ]; then
            while : ; do
                [[ $q -eq 0 ]] && echo "Please enter a new password for the user."
                stty -echo
                echo -en "\033[33m"
                read -p "Password: " p; echo
                read -p "Repeat Password: " pc; echo
                echo -en "\033[0m"
                stty echo
                [[ "$p" == "$pc" ]] && break
                echo -e "\033[31mPassword not matching. Repeat.\033[0m"
            done
            
            [[ $q -eq 0 ]] && echo -e "\e[92mUpdate password in DB...\e[0m"
            sed -i "/^$name\:/d" userpermissions
            ./verify.sh --genhash "$name" "$p" >> userpermissions

            echo -en "${name}\n${p}" > users/$name/authfile
        fi
    fi

    [[ "$a" != "" ]] && USER_IP="$a" || USER_IP=$(sed -nr '1s/^.+ (.+) .+$/\1/p' ../ccd/$name)

    if test $q -eq 0
    then
        while : ; do
            echo "Enter a custom IP address."
            echo "Leave blank if you dont want to make any changes."

            echo -en "\033[33m"
            read -p "IP Address [$USER_IP]: " tUSER_IP;
            echo -en "\033[0m"
            test "$tUSER_IP" = "" && break
            if checkip $tUSER_IP; then
                OLD_IP="$USER_IP"
                USER_IP=$tUSER_IP
                echo -e "\e[92mSetting new static IP...\e[0m"
                echo "ifconfig-push $USER_IP $SUBNET_MASK" > ../ccd/$name

                echo -e "\e[92mUpdate DNS entry...\e[0m"
                sed -i "s/^$OLD_IP /$USER_IP /" /etc/hosts
                systemctl restart dnsmasq

                break
            fi
            echo -e "\033[31mInvalid IP address or already used. Repeat.\033[0m"
        done
    fi

    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build

    ;;
"certrefresh")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name)
    then
        echo -e "\033[31mUsername not found!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mRefreshing certificates for $name...\e[0m"
    
    [[ $q -eq 0 ]] && echo -e "\e[92mAdding old certificate to the revocation list...\e[0m"
    openssl ca -config openssl.cnf -keyfile rootCA.key -cert rootCA.crt -revoke users/$name/client.crt

    [[ $q -eq 0 ]] && echo -e "\e[92mRemove old certificates\e[0m"
    cp -r "users/$name" "users/.deleted/${name}_$(date +"%Y-%m-%d_%k-%M-%S")"
    
    cd users/$name
    rm client.crt
    rm client.csr
    rm client.key
    rm $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cd ../..

    [[ $q -eq 0 ]] && echo -e "\e[92mGenerating new certificate...\e[0m"
    
    [ -d users/$name ] || mkdir users/$name
    
    openssl genrsa -out users/$name/client.key $KEY_SIZE 2>$FP
    openssl req -new -config openssl.cnf -key users/$name/client.key -out users/$name/client.csr -subj "/C=$KEY_COUNTRY/ST=$KEY_PROVINCE/L=$KEY_CITY/O=$KEY_ORG/OU=$KEY_OU/CN=$name"
    yes | openssl ca -config openssl.cnf -keyfile rootCA.key -cert rootCA.crt -out users/$name/client.crt -in users/$name/client.csr -days $KEY_EXPIRE -md sha256 2>$FP

    [[ $q -eq 0 ]] && echo -e "\e[92mExporting new certificates to: $c/$name.zip\e[0m"
    cd users/$name
    
    echo "$(OPENVPN_CLIENT_CONF)" > client.ovpn
    echo "ca rootCA.crt" >> client.ovpn
    echo "cert client.crt" >> client.ovpn
    echo "key client.key" >> client.ovpn

    echo "$(OPENVPN_CLIENT_CONF)" > $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<ca>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat rootCA.crt >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</ca>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<cert>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat client.crt >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</cert>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "<key>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    cat client.key >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn
    echo "</key>" >> $name@$SERVER_NAME.$DOMAIN_NAME.ovpn

    p=$(sed -n '2p' authfile)
    if [ $SINGLE_CERT -eq 0 ]
    then
        zip --password "$p" "$c/$name.zip" client.ovpn rootCA.crt client.crt client.key authfile >$FP
    else
        zip --password "$p" "$c/$name.zip" $name@$SERVER_NAME.$DOMAIN_NAME.ovpn authfile >$FP
    fi
    cd ../..

    ;;
"certexport")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name)
    then
        echo -e "\033[31mUsername not found!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mExporting certificates to: $c/$name.zip\e[0m"
    cd users/$name
    
    p=$(sed -n '2p' authfile)
    if [ $SINGLE_CERT -eq 0 ]
    then
        zip --password "$p" "$c/$name.zip" client.ovpn rootCA.crt client.crt client.key authfile >$FP
    else
        zip --password "$p" "$c/$name.zip" $name@$SERVER_NAME.$DOMAIN_NAME.ovpn authfile >$FP
    fi
    cd ../..

    ;;
"userlist")
    cd $OPENVPN_PATH/versa

    [ -t 1 ] && [[ $q -eq 0 ]] && echo -e "\e[1;92mList all $(wc -l userpermissions | cut -d ' ' -f 1) users...\e[0m" 1>&2

    for i in $(cat userpermissions | sort | cut -d':' -f 1 | tr '\n' ' ')
    do
        [ -t 1 ] && echo -en "\e[1mName: \e[0m" 1>&2
        echo -n  "$i"
        [ -t 1 ] && echo 1>&2

        [ -t 1 ] && echo -en "    \e[1mIP-Address:\e[0m" 1>&2
        echo -n  " $(sed -nr '1s/^.+ (.+) .+$/\1/p' ../ccd/$i)"
        [ -t 1 ] && echo 1>&2

        [ -t 1 ] && echo -en "    \e[1mExpires:\e[0m" 1>&2
        echo -n  " $(sed -nr 's/^.*Not After \: (.*)$/\1/p' users/$i/client.crt | tr ' ' '-')"
        [ -t 1 ] && echo 1>&2

        [ -t 1 ] && echo -en "    \e[1mAccess:\e[0m" 1>&2
        echo -n  " $(sed -nr "/^$i:/p" userpermissions | cut -d':' -f 3)"
        [ -t 1 ] && echo 1>&2

        [ -t 1 ] && echo -en "    \e[1mTargetgroup:\e[0m" 1>&2
        echo -n  " $(sed -nr "/^$i:/p" userpermissions | cut -d':' -f 4)"
        [ -t 1 ] && echo 1>&2

        [ -t 1 ] && echo -en "    \e[1mEnabled:\e[0m" 1>&2
        echo -n  " $(sed -nr "/^$i:/p" userpermissions | cut -d':' -f 5)"
        [ -t 1 ] && echo 1>&2

        echo
    done
    
    ;;
"userinfo")
    cd $OPENVPN_PATH/versa
    [ -t 1 ] && [[ $q -eq 0 ]] && echo -e "\e[1;92mShow info from $name\e[0m" 1>&2

    [ -t 1 ] && echo -en "\e[1mName: \e[0m" 1>&2
    echo -n  "$name"
    [ -t 1 ] && echo 1>&2

    [ -t 1 ] && echo -en "    \e[1mIP-Address:\e[0m" 1>&2
    echo -n  " $(sed -nr '1s/^.+ (.+) .+$/\1/p' ../ccd/$name)"
    [ -t 1 ] && echo 1>&2

    [ -t 1 ] && echo -en "    \e[1mExpires:\e[0m" 1>&2
    echo -n  " $(sed -nr 's/^.*Not After \: (.*)$/\1/p' users/$name/client.crt | tr ' ' '-')"
    [ -t 1 ] && echo 1>&2

    [ -t 1 ] && echo -en "    \e[1mAccess:\e[0m" 1>&2
    echo -n  " $(sed -nr "/^$name:/p" userpermissions | cut -d':' -f 3)"
    [ -t 1 ] && echo 1>&2

    [ -t 1 ] && echo -en "    \e[1mTargetgroup:\e[0m" 1>&2
    echo -n  " $(sed -nr "/^$name:/p" userpermissions | cut -d':' -f 4)"
    [ -t 1 ] && echo 1>&2

    [ -t 1 ] && echo -en "    \e[1mEnabled:\e[0m" 1>&2
    echo -n  " $(sed -nr "/^$name:/p" userpermissions | cut -d':' -f 5)"
    [ -t 1 ] && echo 1>&2

    echo
    ;;
"userenable")
    cd $OPENVPN_PATH/versa
    
    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    GET_USERDATA $name
    
    if [[ $p5 -eq 1 ]] ; then
        echo -e "\033[31mUser is already enabled!\033[0m"
        exit 1
    fi
        
    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "1"
    
    [[ $q -eq 0 ]] && echo -e "\e[1;92m$name enabled.\e[0m"
    ;;
"userdisable")
    cd $OPENVPN_PATH/versa
    
    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    GET_USERDATA $name
    
    if [[ $p5 -eq 0 ]] ; then
        echo -e "\033[31mUser is already disabled!\033[0m"
        exit 1
    fi
        
    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "0"
    
    [[ $q -eq 0 ]] && echo -e "\e[1;92m$name disabled.\e[0m"
    ;;
"rebuild")
    cd $OPENVPN_PATH/versa
    
    [[ $q -eq 0 ]] && echo -e "\e[1;92mRebuild all congigurations...\e[0m"

    [[ $q -eq 0 ]] && echo -e "\e[92mClean all external configurations...\e[0m"
    versa_clean

    [[ $q -eq 0 ]] && echo -e "\e[92mGenerate all external configurations...\e[0m"
    versa_build

    ;;
"clean")
    cd $OPENVPN_PATH/versa
    
    [[ $q -eq 0 ]] && echo -e "\e[1;92mClean all congigurations...\e[0m"
    versa_clean

    ./editIt.sh delete /etc/sysctl.conf VERSA_REDIRECT 0

    ;;
"useraccessadd")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    if !(VLAN_EXIST $name2); then
        echo -e "\033[31mGroup not found!\033[0m"
        exit 1
    fi
        
    GET_USERDATA $name
    
    if [[ $p3 =~ $name2 ]] ; then
        echo -e "\033[31mUser already has this access permission!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mAdding $name to accesgroup $name2\e[0m"
    
    test -n "$p3" && op3="$p3,"
    p3="${op3}$name2"

    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "$p5"
    
    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build

    ;;
"useraccessdel")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    if !(VLAN_EXIST $name2); then
        echo -e "\033[31mGroup not found!\033[0m"
        exit 1
    fi

    GET_USERDATA $name
    
    if !([[ $p3 =~ $name2 ]]) ; then
        echo -e "\033[31mUser is not member of this group!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mRemoving $name from accesgroup $name2\e[0m"
    
    test "$p3" = "$name2" && p3=""
    p3=$(echo "$p3" | sed "s/^$name2,//")
    p3=$(echo "$p3" | sed "s/,$name2//")

    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "$p5"
    
    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build

    ;;
"usertargetadd")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    if !(VLAN_T_EXIST $name2); then
        echo -e "\033[31mGroup not found or cannot act as a target group!\033[0m"
        exit 1
    fi

    GET_USERDATA $name
    
    if [[ $p4 =~ $name2 ]] ; then
        echo -e "\033[31mUser already is a member of this target group!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mAdding $name to targetgroup $name2\e[0m"
    
    test -n "$p4" && op4="$p4,"
    p4="${op4}$name2"

    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "$p5"
    
    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build
    
    ;;
"usertargetdel")
    cd $OPENVPN_PATH/versa

    if !(USER_EXIST $name); then
        echo -e "\033[31mUser not found!\033[0m"
        exit 1
    fi
    
    if !(VLAN_EXIST $name2); then
        echo -e "\033[31mGroup not found!\033[0m"
        exit 1
    fi

    GET_USERDATA $name
    
    if !([[ $p4 =~ $name2 ]]) ; then
        echo -e "\033[31mUser is not member of this group!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mRemoving $name from targetgroup $name2\e[0m"
    
    test "$p4" = "$name2" && p4=""
    p4=$(echo "$p4" | sed "s/^$name2,//")
    p4=$(echo "$p4" | sed "s/,$name2//")

    SET_USERDATA "$p1" "$p2" "$p3" "$p4" "$p5"
    
    [[ $q -eq 0 ]] && echo -e "\e[92mRebuild all external configurations...\e[0m"
    versa_clean
    versa_build

    ;;
"test")
    cd $OPENVPN_PATH/versa
    
    vlan_exist $name && echo "VLAN EXIST!" || echo "VLAN NOT EXIST!"
    user_exist $name && echo "USER EXIST!" || echo "USER NOT EXIST!"
    ;;
"nextfreeip") #UNDOCUMENTED!
    cd $OPENVPN_PATH/versa
    searchip
    ;;
"vlanlist")
    cd $OPENVPN_PATH/versa

    if [[ $u -eq 1 ]]; then
        echo -n "${GROUP_NAME[*]}"
        exit 0
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mList all ${#GROUP_NAME[*]} groups...\e[0m"
    
    for (( i=0; i<${#GROUP_NAME[*]}; i++ ))
    do
        gn="${GROUP_NAME[$i]}"
        gr="${GROUP_VLAN_RULE[$i]}"
        echo -e "\e[1mName: \e[21m$gn"
        echo -en "    \e[1mAccess User: \e[21m"

        for j in $(cat userpermissions); do
            p1="$(echo "$j" | cut -d':' -f 1)"
            p3="$(echo "$j" | cut -d':' -f 3)"

            if test -n "$(echo "$p3" | sed -n "/$gn/p")"; then
                echo -n "$p1 "
            fi
        done

        echo ""
        echo -en "    \e[1mTarget User: \e[21m"

            if VLAN_T_EXIST $gn ; then
                for j in $(cat userpermissions); do
                    p1="$(echo "$j" | cut -d':' -f 1)"
                    p4="$(echo "$j" | cut -d':' -f 4)"

                    if test -n "$(echo "$p4" | sed -n "/$gn/p")"; then
                        echo -n "$p1 "
                    fi
                done
            else
                echo -en "\033[31m(Not a target-group)\033[0m"
            fi

        echo ""
        echo ""
    done

    ;;
"vlaninfo")
    cd $OPENVPN_PATH/versa

    if !(VLAN_EXIST $name); then
        echo -e "\033[31mGroup not found!\033[0m"
        exit 1
    fi

    [[ $q -eq 0 ]] && echo -e "\e[1;92mList informations about $name...\e[0m"
    
    for (( i=0; i<${#GROUP_NAME[*]}; i++ ))
    do
        gn="${GROUP_NAME[$i]}"
        gr="${GROUP_VLAN_RULE[$i]}"

        [[ "$gn" != "$name" ]] && continue

        echo -e "\e[1mName: \e[21m$gn"
        echo -en "    \e[1mAccess User: \e[21m"

        for j in $(cat userpermissions); do
            p1="$(echo "$j" | cut -d':' -f 1)"
            p3="$(echo "$j" | cut -d':' -f 3)"

            if test -n "$(echo "$p3" | sed -n "/$gn/p")"; then
                echo -n "$p1 "
            fi
        done

        echo ""
        echo -en "    \e[1mTarget User: \e[21m"

            if VLAN_T_EXIST $gn ; then
                for j in $(cat userpermissions); do
                    p1="$(echo "$j" | cut -d':' -f 1)"
                    p4="$(echo "$j" | cut -d':' -f 4)"

                    if test -n "$(echo "$p4" | sed -n "/$gn/p")"; then
                        echo -n "$p1 "
                    fi
                done
            else
                echo -en "\033[31m(Not a target-group)\033[0m"
            fi

        echo ""
        echo ""
    done

    ;;
*)
    echo -e "\033[31mUnknown option!\033[0m"
    ;;
esac
