import socketserver
import uuid
import queue
import os
import time
import threading

connections = {}
base_dir = '/usr/src/app/c2/'


class InvalidConnUUID(Exception):
    pass


class NotAliveConnection(Exception):
    pass


class C2TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        global connections
        conn_uuid = uuid.uuid4().hex
        conn_folder = base_dir + conn_uuid
        os.mkdir(conn_folder)
        connections[conn_uuid] = {'cmd_queue': queue.Queue(), 'last_seen': time.time(),
                                  'client_addr': self.client_address, 'is_alive': True, 'short_log': b''}
        short_log_size = 100
        log_file = conn_folder + '/log_file'
        hello = self.request.recv(6).strip()
        log_handler = open(log_file, 'wb')
        log_handler.write(hello)
        connections[conn_uuid]['short_log'] += hello
        close = False
        while not close:
            command = connections[conn_uuid]['cmd_queue'].get()
            command = command.encode()
            self.request.sendall(command + b'\n')
            log_handler.write(b'\n' + command + b'\n')
            connections[conn_uuid]['short_log'] += b'\n' + command + b'\n'
            connections[conn_uuid]['short_log'] = connections[conn_uuid]['short_log'][-short_log_size:]
            if b'close' in command:
                close = True
            else:
                # TODO: per-command logic
                # TODO: implement a poll meta-command to call 'recv' multiple times
                try:
                    # wait a second that more data is available
                    time.sleep(1)
                    data = self.request.recv(4096)
                    log_handler.write(data)
                    connections[conn_uuid]['short_log'] += data
                    connections[conn_uuid]['last_seen'] = time.time()
                except TimeoutError:
                    data = b"\n[*] Connection closed for timeout error\n"
                    log_handler.write(data)
                    connections[conn_uuid]['short_log'] += data
                    close = True
                connections[conn_uuid]['short_log'] = connections[conn_uuid]['short_log'][-short_log_size:]
        connections[conn_uuid]['is_alive'] = False
        log_handler.close()


def start_multithreaded_c2(config):
    host, port = '0.0.0.0', config['c2_port']
    server = socketserver.ThreadingTCPServer((host, port), C2TCPHandler)
    server.timeout = 30
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    return server


def list_c2_connections():
    global connections
    conn_tuples = []
    for conn_uuid in connections:
        client_addr = connections[conn_uuid]['client_addr']
        last_seen = connections[conn_uuid]['last_seen']
        is_alive = connections[conn_uuid]['is_alive']
        conn_tuples.append((conn_uuid, client_addr, last_seen, is_alive))
    return conn_tuples


def send_c2_command(conn_uuid, command):
    global connections
    if conn_uuid not in connections:
        raise InvalidConnUUID
    if not connections[conn_uuid]['is_alive']:
        raise NotAliveConnection
    connections[conn_uuid]['cmd_queue'].put(command)


def read_c2_log(conn_uuid):
    global connections
    if conn_uuid not in connections:
        raise InvalidConnUUID
    data = connections[conn_uuid]['short_log']
    data = data.decode(errors='replace')
    return data
