#!/bin/sh
# Blackbox tests for ldap search via net ads
# Copyright (C) 2015 Uri Simchoni <urisimchoni@gmail.com>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_net_ads_search.sh DOMAIN REALM USER PASSWORD PREFIX
EOF
exit 1;
fi

DOMAIN=$1
REALM=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5

bindir="$BINDIR"
net_tool="$bindir/net"
wbinfo_tool="$bindir/wbinfo"

. `dirname $0`/subunit.sh

CONFIG="--configfile=$PREFIX/etc/smb.conf"
export CONFIG

testit "net ads user" $VALGRIND $net_tool ads user  -U$USERNAME%$PASSWORD  || failed=`expr $failed + 1`
testit "net ads user - machine account" $VALGRIND $net_tool ads user -kP  || failed=`expr $failed + 1`
# verify we're not cheating and exercise some failure path...
testit_expect_failure "net ads user wrong password" $VALGRIND $net_tool ads user  -U$USERNAME%wrongpassword  || failed=`expr $failed + 1`
#some more search commands
testit "net ads group" $VALGRIND $net_tool ads group  -U$USERNAME%$PASSWORD  || failed=`expr $failed + 1`
testit "net ads search" $VALGRIND $net_tool ads search '(objectCategory=group)' sAMAccountName -U$USERNAME%$PASSWORD  || failed=`expr $failed + 1`
DN="CN=administrator,CN=Users,DC=`echo -n \"$REALM\" | sed s/\\\\./,DC=/g`"
testit "net ads dn" $VALGRIND $net_tool ads dn $DN sAMAccountName -U$USERNAME%$PASSWORD  || failed=`expr $failed + 1`

testok $0 $failed
