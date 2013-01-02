#!/bin/bash
# Simple test script
# Glen Ogilvie
#
# Requires:
# sqlite, basename, which, egrep, dbconf, yubserve.py running, bash, curl

PATH="../:$PATH"
Black="$(tput setaf 0)"
BlackBG="$(tput setab 0)"
DarkGrey="$(tput bold ; tput setaf 0)"
LightGrey="$(tput setaf 7)"
LightGreyBG="$(tput setab 7)"
White="$(tput bold ; tput setaf 7)"
Red="$(tput setaf 1)"
RedBG="$(tput setab 1)"
LightRed="$(tput bold ; tput setaf 1)"
Green="$(tput setaf 2)"
GreenBG="$(tput setab 2)"
LightGreen="$(tput bold ; tput setaf 2)"
Brown="$(tput setaf 3)"
BrownBG="$(tput setab 3)"
Yellow="$(tput bold ; tput setaf 3)"
Blue="$(tput setaf 4)"
BlueBG="$(tput setab 4)"
LightBlue="$(tput bold ; tput setaf 4)"
Purple="$(tput setaf 5)"
PurpleBG="$(tput setab 5)"
Pink="$(tput bold ; tput setaf 5)"
Cyan="$(tput setaf 6)"
CyanBG="$(tput setab 6)"
LightCyan="$(tput bold ; tput setaf 6)"
bold=$(tput bold)
reset=$(tput sgr0)

echo "${Yello}SQLlite testing${reset}"

DBCONF=`which dbconf.py`
if [ ! -f "$(dirname $DBCONF)/yubikeys.sqlite" ] ; then echo "Sorry, can't find `dirname $DBCONF`/yubikeys.sqlite"; exit 1; fi

echo "${LightBlue}Reset yubikey to known state${reset}"
dbconf.py -yk nelg
dbconf.py -ya nelg hihrhghufvfi 676f6e656c67 89eb6d3d930077b427a88760db0fc375
sqlite $(dirname $DBCONF)/yubikeys.sqlite "update yubikeys set counter=768, time=10864886, aeskey='89eb6d3d930077b427a88760db0fc375' where nickname = 'nelg';"
dbconf.py -yl

echo "${Purple}Disable yubikey.  The following test should show BAD_OTP${reset}"
dbconf.py -yd nelg
curl http://localhost:8000/wsapi/2.0/verify?id=1\&otp=hihrhghufvfibbbekurednelnklnulclbiubvjrenlii

echo "${Purple}Enable yubikey.  The following test should show OK${reset}"
dbconf.py -ye nelg
curl http://localhost:8000/wsapi/2.0/verify?id=1\&otp=hihrhghufvfibbbekurednelnklnulclbiubvjrenlii
echo

echo "${Cyan}Healthcheck. (/healthcheck?service=yubikeys), expected result should be OK"
curl -s 'http://localhost:8000/healthcheck?service=yubikeys'
echo "${reset}"

echo "${Purple}Replay yubikey.  The following test should show REPLAYED_OTP${reset}"
curl http://localhost:8000/wsapi/2.0/verify?id=1\&otp=hihrhghufvfibbbekurednelnklnulclbiubvjrenlii

echo
echo "${LightBlue}Reset oath to known state${reset}"
dbconf.py -hk Test
dbconf.py -ha Test testtesttest e623694b2621a6eda41d9380c3dfc4fd67ffadb9
echo "${Pink}Test OATH.  The following test should show OK${reset}"
curl 'http://localhost:8000/wsapi/2.0/oathverify?otp=534088&publicid=testtesttest'
echo

echo "${Cyan}Healthcheck. (/healthcheck?service=oathtokens), expected result should be OK"
curl -s 'http://localhost:8000/healthcheck?service=oathtokens'
echo
echo "${Cyan}Healthcheck. (/healthcheck), expected result should be OK"
curl -s 'http://localhost:8000/healthcheck'
echo "${reset}"

echo "${Pink}Replay OATH.  The following test should show NO_AUTH${reset}"
curl 'http://localhost:8000/wsapi/2.0/oathverify?otp=534088&publicid=testtesttest'

echo
echo "${Pink}Disable OATH.  The following test should show BAD_OTP${reset}"
dbconf.py -hd Test
curl 'http://localhost:8000/wsapi/2.0/oathverify?otp=389694&publicid=testtesttest'
echo
echo "${Pink}Enable OATH.  The following test should show OK${reset}"
dbconf.py -he Test
curl 'http://localhost:8000/wsapi/2.0/oathverify?otp=389694&publicid=testtesttest'

echo
echo "${LightBlue}Setting test keys to disabled for security${reset}"
dbconf.py -yd nelg
dbconf.py -hd Test
echo
echo "${Cyan}Healthcheck. (/healthcheck), expected result should be WARN for both services"
curl -s 'http://localhost:8000/healthcheck'
echo "${reset}"
dbconf.py -yl | egrep "database|Public|nelg"
dbconf.py -hl | egrep "database|Public|Test"
echo
echo "${Red}WARNING: Test keys have been added to the default sqlite database."
echo "To remove the test keys, run the following: "
echo "${bold}`which dbconf.py` -hk Test; `which dbconf.py` -yk nelg ${reset}"
