#!/bin/bash

BINARY=src/textglass_client

if [ ! -f "$BINARY" ]
then
    echo "Please run compile.sh"
    exit 1
fi

valgrind $BINARY "$@"
