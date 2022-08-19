import socketserver
import os
import threading
from injector import command_line_interface


class CmdLineTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        os.dup2(self.request.fileno(), 0)
        os.dup2(self.request.fileno(), 1)
        os.dup2(self.request.fileno(), 2)
        command_line_interface(self.server.kcaldera_config, self.server.kcaldera_offsets)


def start_multiprocess_cmd_line_interface(config, offsets):
    host, port = '0.0.0.0', config['text_ui_port']
    server = socketserver.ForkingTCPServer((host, port), CmdLineTCPHandler)
    server.timeout = 2
    server.kcaldera_config = config
    server.kcaldera_offsets = offsets
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    return server
