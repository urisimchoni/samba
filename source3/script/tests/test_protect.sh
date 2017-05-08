#!/bin/bash
#
# Blackbox test for protect VFS module.
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_protect SERVER SERVER_IP USERNAME PASSWORD WORKDIR SMBCLIENT PARAMS
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
USERNAME=${3}
PASSWORD=${4}
WORKDIR=${5}
SMBCLIENT=${6}
shift 6
ADDARGS="$*"
SMBCLIENT="$VALGRIND ${SMBCLIENT} ${ADDARGS}"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

# build a hierarchy of dirs
build_files()
{
    local destdir
    destdir=$1

    rm -rf $destdir/* > /dev/null
    mkdir -p $destdir
    mkdir -p $destdir/bar/baz
    mkdir -p $destdir/bar/foo
}

test_rmdir()
{
    local share
    local path
    local expect
    local base
    local expect_d
    local out
    local denied
    local still_here

    share=$1
    path=$2
    expect=$3
    base=$(basename $path)

    build_files $WORKDIR

    if [ "$expect" = "0" ] ; then
        expect_d="allowed"
    else
        expect_d="denied"
    fi

    #verify it's here...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path")
    if ! echo "$out" | grep -qi "$base[[:space:]]*D" ; then
        echo -e "expected $path to initially exist, got:\n$out"
        return 1
    fi

    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "rmdir $path")
    if echo "$out" | grep -q "NT_STATUS_ACCESS_DENIED" ; then
        denied="denied"
    else
        denied="allowed"
    fi
    if [ "$expect_d" != "$denied" ] ; then
        echo -e "expected rmdir $path to be $expect_d, got:\n$out"
        return 1
    fi

    #verify it's here/gone...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path")
    if echo "$out" | grep -qi "$base[[:space:]]*D" ; then
        still_here="0"
    else
        still_here="1"
    fi

    if [ "$still_here" = "0" ] && [ "$expect" = "0" ]; then
        echo -e "expected $path to be deleted but it's still here:\n$out"
        return 1
    fi

    if [ "$still_here" != "0" ] && [ "$expect" != "0" ]; then
        echo -e "expected $path to be protected but it's gone:\n$out"
        return 1
    fi

}

test_rename()
{
    local share
    local path
    local expect
    local base
    local expect_d
    local out
    local denied
    local still_here

    share=$1
    path=$2
    expect=$3
    base=$(basename $path)

    build_files $WORKDIR

    if [ "$expect" = "0" ] ; then
        expect_d="allowed"
    else
        expect_d="denied"
    fi

    #verify it's here...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path")
    if ! echo "$out" | grep -qi "$base[[:space:]]*D" ; then
        echo -e "expected $path to initially exist, got:\n$out"
        return 1
    fi

    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "rename $path $path.new")
    if echo "$out" | grep -q "NT_STATUS_ACCESS_DENIED" ; then
        denied="denied"
    else
        denied="allowed"
    fi
    if [ "$expect_d" != "$denied" ] ; then
        echo -e "expected rename $path to be $expect_d, got:\n$out"
        return 1
    fi

    #verify it's here/gone...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path")
    if echo "$out" | grep -qi "$base[[:space:]]*D" ; then
        still_here="0"
    else
        still_here="1"
    fi

    if [ "$still_here" = "0" ] && [ "$expect" = "0" ]; then
        echo -e "expected $path to be renamed but it's still here:\n$out"
        return 1
    fi

    if [ "$still_here" != "0" ] && [ "$expect" != "0" ]; then
        echo -e "expected $path to be protected but it's gone:\n$out"
        return 1
    fi

}

test_supersede()
{
    local share
    local path
    local expect
    local base
    local expect_d
    local out
    local denied
    local superseded

    share=$1
    path=$2
    expect=$3
    base=$(basename $path)

    build_files $WORKDIR

    if [ "$expect" = "0" ] ; then
        expect_d="allowed"
    else
        expect_d="denied"
    fi

    #verify it's here...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path")
    if ! echo "$out" | grep -qi "$base[[:space:]]*D" ; then
        echo -e "expected $path to initially exist, got:\n$out"
        return 1
    fi

    #make a different dir
    $SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "mkdir new; mkdir new/inside"

    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "rename new $path -f")
    if echo "$out" | grep -q "NT_STATUS_INVALID_PARAMETER" ; then
        echo "SMB1 - no support for superseding"
        return 0
    fi

    if echo "$out" | grep -q "NT_STATUS_ACCESS_DENIED" ; then
        denied="denied"
    else
        denied="allowed"
    fi
    if [ "$expect_d" != "$denied" ] ; then
        echo -e "expected supersede $path to be $expect_d, got:\n$out"
        return 1
    fi

    #verify it's here/gone...
    out=$($SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$share" -I $SERVER_IP -c "ls $path/inside")
    if echo "$out" | grep -q "inside[[:space:]]*D" ; then
        superseded="0"
    else
        superseded="1"
    fi

    if [ "$superseded" != "0" ] && [ "$expect" = "0" ]; then
        echo -e "expected $path to be superseded but it wasn't:\n$out"
        return 1
    fi

    if [ "$superseded" = "0" ] && [ "$expect" != "0" ]; then
        echo -e "expected $path to be protected but it's superseded:\n$out"
        return 1
    fi

}

failed=0

testit "removing regular dir" test_rmdir protect bar/foo 0 || failed=`expr $failed + 1`
testit "removing protected dir" test_rmdir protect bar/baz 1 || failed=`expr $failed + 1`
testit "removing protected dir (case)" test_rmdir protect bar/baZ 1 || failed=`expr $failed + 1`
testit "renaming regular dir" test_rename protect bar/foo 0 || failed=`expr $failed + 1`
testit "renaming protected dir" test_rename protect bar/baz 1 || failed=`expr $failed + 1`
testit "renaming protected dir (case)" test_rename protect bar/baZ 1 || failed=`expr $failed + 1`
testit "superseding regular dir" test_supersede protect bar/foo 0 || failed=`expr $failed + 1`
testit "supersering protected dir" test_supersede protect bar/baz 1 || failed=`expr $failed + 1`
testit "superseding protected dir (case)" test_supersede protect bar/baZ 1 || failed=`expr $failed + 1`

exit $failed
