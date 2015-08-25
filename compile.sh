#!/bin/bash

set -e

cd src

if [ "$1" = "clean" ]
then
    echo "Cleaning"

    make clean

    exit 0
fi

echo "Compiling"

make
