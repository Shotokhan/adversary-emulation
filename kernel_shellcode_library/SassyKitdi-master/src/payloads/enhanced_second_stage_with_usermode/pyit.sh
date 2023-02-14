#!/bin/bash

python3 ../../shellcode.py target/x86_64-pc-windows-gnu/release/k_agent_with_usermode.dll | grep -v '/tmp/' > /tmp/hexwut

gedit /tmp/hexwut
