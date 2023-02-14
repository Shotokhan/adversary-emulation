# SassyKitdi

See writeup at https://zerosum0x0.blogspot.com/2020/08/sassykitdi-kernel-mode-tcp-sockets.html

## Study

You can view the generated shellcode in assembly.txt

Most of the code of interest is in the src/common/ntmem (LSASS dump) and src/common/nttdi (TCP sockets) libraries. All structs, types, function signatures, etc are in src/common/ntdef. The shellcode project is in src/payloads/sassykitdi.

Tested on Windows 10.0.18362.1016. Might require some tweaking for other versions but all APIs used are available since Win2k.

## Build/Run

Install gcc-mingw-w64 and Rustup with x86_64-windows-pc-gnu target.

In src/payloads/sassykitdi there is build.sh and pyit.sh to build the project and scrape the shellcode out of the DLL. The big endian reverse address/port should be changed in the source.

There is also src/socketdump.py server which will wait to receive SassyKitdi connections and create a minidump file.

## Exploit Preambles

SassyKitdi must be performed at PASSIVE_LEVEL. To use the sample project in an exploit payload, you will need to provide your own exploit preamble. This is the unique part of the exploit that cleans up the stack frame, and in e.g. EternalBlue lowers the IRQL from DISPATCH_LEVEL.

## Other Notes

The Rust code compiler generated size is ~3300 bytes, but includes many safety checks and early bailouts. Hand optimization could go down to ~2500 bytes, perhaps further with less safety checks.

## Disclaimer 

Code is provided for educational purposes and is unfriendly due to my laziness. I am not responsible for anyone's actions, including my own, and am warning you not to do illegal things.
