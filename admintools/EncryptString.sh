#!/bin/bash
#-
#- Usage:
#-  ./GenerateEncryptedString.sh StringToEncrypt
#-
#-  ------
#-  eval $( path/to/GenerateEncryptedString.sh StringToEncrypt )
#-  echo "$StringToEncrypt" "$Salt" "$Passphrase"
#-

if [ "$#" -eq 0 ]; then
    /usr/bin/grep ^#- "$0" | /usr/bin/cut -c 4-
    exit 1
fi

STRING="$1"
SALT="$(/usr/bin/openssl rand -hex 8)"
PASSPHRASE="$(/usr/bin/openssl rand -hex 12)"
ENCRYPTED="$(echo "$STRING" | /usr/bin/openssl enc -aes256 -a -A -S "$SALT" -k "$PASSPHRASE")"

echo Salt=\'"$SALT"\'
echo Passphrase=\'"$PASSPHRASE"\'
echo Saltphrase=\'"${SALT}:${PASSPHRASE}"\'
echo EncryptedString=\'"$ENCRYPTED"\'

# vim: set ts=4 sw=4 sts=0 ft=sh fenc=utf-8 ff=unix :
