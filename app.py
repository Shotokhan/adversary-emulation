from flask import Flask, redirect
from config.conf_manager import read_config
from injector import start_c2, stop_c2
from cmd_line_over_network import start_multithreaded_cmd_line_interface


app = Flask(__name__, static_url_path='', static_folder='/usr/src/app/c2/connections/')


@app.route('/')
def index():
    return redirect('/connections.json')


if __name__ == "__main__":
    config = read_config('/usr/src/app/config/config.json')
    offsets = read_config('/usr/src/app/kernel_shellcode_library/offsets.json')
    c2_server = start_c2(config)
    c2_ui = start_multithreaded_cmd_line_interface(config, offsets)
    app.run(host='0.0.0.0', port=config['flask_port'])
    c2_ui.shutdown()
    stop_c2(c2_server)
