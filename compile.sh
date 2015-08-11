#!/bin/bash

set -e

cd src

echo "Cleaning"

make clean

if [ "$1" = "clean" ]
then
    exit 0
fi

echo "Compiling"

make
