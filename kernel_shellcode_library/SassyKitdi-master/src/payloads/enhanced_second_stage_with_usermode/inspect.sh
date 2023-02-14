#!/bin/bash

objdump -M intel -D ./target/x86_64-pc-windows-gnu/release/k_agent_with_usermode.dll | grep '<_DllMainCRTStartup>:' -A 5000 | less
