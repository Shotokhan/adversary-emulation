from c2.c2_server import read_c2_log


# TODO: improve local_users_parser and generic_dir_parser, they don't make the check well

def null_parser(conn_uuid, cmd_indexes_list):
    return []


def local_users_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[0]
    data = read_c2_log(conn_uuid, index).split('\n')[1:]
    not_local_users = ['directory opened, sending files', '.', '..', 'All Users', 'Default',
                       'Default User', 'desktop.ini', 'Public', 'directory listing finished', '']
    local_users = []
    for line in data:
        line = line.strip()
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
                  'desktop.ini']
    target = []
    for line in data:
        line = line.strip()
        if line not in not_target:
            target.append(base_dir + line)
    if len(target) == 0:
        return [('staged_files', target)]
    else:
        # a default target file, can be overwritten
        return [('staged_files', target),
                ('target_file', target[0])]


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
