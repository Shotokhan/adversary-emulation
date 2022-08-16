#!/bin/bash
if [ $# != 1 ]; then
	echo "Usage: $0 file.bin"
else
	objdump -M intel,x86-64 -b binary -D -mi386 $1 | less
fi
