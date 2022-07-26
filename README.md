# adversary-emulation

Project in progress :p

Windows VM version: 10 Home, build 19041, KVA Shadowing enabled, kernel debug with KDNET, libvirt XML modified to have file-backed RAM on a link to /dev/shm (file-mapped on RAM) and to have e1000 NIC (for compatibility with KDNET)
Rust version: rustc 1.63.0-nightly (12cd71f4d 2022-06-01)
Cargo version: cargo 1.63.0-nightly (38472bc19 2022-05-31)
Volatility version: Volatility 3 Framework 1.0.0
qemu-system-x86\_64 version: qemu-5.2.0-9.fc34
Libvirt version (virsh & libvirtd): 7.0.0
Linux host version: 5.12.14-200.fc33.x86\_64

