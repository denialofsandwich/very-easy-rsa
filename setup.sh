#!/bin/bash

export SPWD="$( cd "$(dirname "$0")" ; pwd -P )"
cd "$SPWD"

mkdir -p /etc/versa
cp versa-config-example.sh /etc/versa/config.sh
chown root:root /etc/versa/config.sh
chmod 755 /etc/versa/config.sh

rm /usr/bin/versa 2> /dev/null
cp -l versa.sh /usr/bin/versa
chown root:root /usr/bin/versa
chmod 755 /usr/bin/versa

echo "Done!"
