#!/bin/bash

export SPWD="$( cd "$(dirname "$0")" ; pwd -P )"
cd "$SPWD"

mkdir -P /etc/versa
cp versa-config-example.sh /etc/versa/config.sh

rm /usr/bin/versa 2> /dev/null
cp -f versa.sh /usr/bin/versa

echo "Done!"
