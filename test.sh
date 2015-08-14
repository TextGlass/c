#!/bin/bash

ROOT=../reference/domains
DOMAINS=`find $ROOT -maxdepth 1 -type d | grep -v "domains$" | sort | xargs echo`

function error
{
    echo "Please pass in a valid reference domain root"
    echo "Or run ./test.sh from SVN"
    exit 1
}

if [ "$1" != "" ]
then
    DOMAINS=$@
fi

if [ "$DOMAINS" = "" ]
then
    error
fi

FAIL=
PASS=

for DROOT in $DOMAINS
do
    DOMAIN=`basename $DROOT`

    if [ ! -d $DROOT -o "`ls $DROOT 2> /dev/null | grep pattern`" = "" ]
    then
        continue
    fi

    echo
    echo "Testing domain: $DOMAIN"

    P=`find $DROOT -type f | grep pattern | grep -v patch | sort | sed "s/^/-p /" | xargs echo`
    PP=`find $DROOT -type f | grep pattern | grep patch | sort | sed "s/^/-pp /" | xargs echo`
    A=`find $DROOT -type f | grep attribute | grep -v patch | sort | sed "s/^/-a /" | xargs echo`
    AP=`find $DROOT -type f | grep attribute | grep patch | sort | sed "s/^/-ap /" | xargs echo`
    T=`find $DROOT -type f | grep test | sort | sed "s/^/-t /" | xargs echo`

    CMD="`echo ./run.sh $P $PP $A $AP $T -q`"

    echo "CMD: $CMD"

    $CMD

    if [ "$?" != "0" ]
    then
        FAIL="$FAIL $DOMAIN"
    else
        PASS="$PASS $DOMAIN"
    fi
done

if [ "$FAIL" != "" ]
then
    echo
    echo "The following tests have failed:$FAIL"
    exit 1
fi

if [ "$PASS" != "" ]
then
    echo
    echo "All tests have passed:$PASS"
    exit 0
fi

error

