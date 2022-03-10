#!/bin/bash
# Updates FortiSOAR Root CA and renew all services certificates
if [ "$EUID" -ne 0 ]
  then echo "Please run $0 script as root"
  exit 0
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

CEXP=$(cat /etc/pki/ca-trust/source/anchors/cs.loc.root.crt | openssl x509 -noout -enddate)
echo -e "Current Root CA Expiry Date:${RED} $CEXP ${RESET}"


TMP_DIR="/tmp/temp_cert"
mkdir -p $TMP_DIR && cd $TMP_DIR
openssl genrsa -out cs.loc.root.key 2048
openssl req -x509 -sha256 -new -nodes -key cs.loc.root.key -days 1825 -out cs.loc.root.crt -subj "/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=FortiSOAR/CN=fortisoar.localhost"
mv -f cs.loc.root.key /etc/pki/cyops/ && mv -f cs.loc.root.crt /etc/pki/ca-trust/source/anchors
status=$?
if [ $status -eq 0 ];then
NEXP=$(cat /etc/pki/ca-trust/source/anchors/cs.loc.root.crt | openssl x509 -noout -enddate)
echo -e "Updated Root CA Expiry Date:${GREEN} $NEXP ${RESET}"
else
echo "Copy new files failed"
exit -1
fi
csadm certs --generate `hostname`
csadm services --restart
