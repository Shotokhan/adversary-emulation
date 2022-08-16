#!/bin/bash
if [ $# != 3 ]; then
	echo "Usage: $0 file.bin new_addr offset"
else
	python customize_shellcode.py --offset $3 --filename $1 --data $2
fi 
