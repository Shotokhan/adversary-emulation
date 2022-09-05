from flask import Flask, redirect, render_template, request
from werkzeug.security import safe_join
import datetime
import os
from config.conf_manager import read_config
from injector import start_c2, stop_c2
from cmd_line_over_network import start_multiprocess_cmd_line_interface
from c2.c2_server import list_c2_connections, ConnectionStorage


app = Flask(__name__, static_url_path='', static_folder='/usr/src/app/c2/connections/',
            template_folder='/usr/src/app/templates/')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/connections')
def list_connections():
    connections = list_c2_connections()
    new_connections = []
    for conn in connections:
        last_seen = datetime.datetime.fromtimestamp(conn[2]).ctime()
        new_conn = (conn[0], str(conn[1]), last_seen, 'Yes' if conn[3] else 'No', str(conn[4]))
        new_connections.append(new_conn)
    return render_template('connections.html', connections=new_connections)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html')
    elif request.method == 'POST':
        f = request.files['file']
        f.save(safe_join(app.static_folder, 'upload_dir', f.filename))
        return redirect('/listdir/upload_dir')


@app.route('/listdir/<subdir>')
def list_subdir(subdir):
    connectionStorage = ConnectionStorage()
    uuid_list = [conn_uuid for conn_uuid in connectionStorage.connections.keys()]
    allowed = uuid_list + ['upload_dir']
    if subdir not in allowed:
        return redirect('/error?error_msg=Error%3A%20dir%20specified%20is%20not%20allowed')
    else:
        files = os.listdir(safe_join(app.static_folder, subdir))
        return render_template('listdir.html', files=files, subdir=subdir)


@app.route('/error')
def error():
    return render_template('error.html', error_msg=request.args.get('error_msg'))


if __name__ == "__main__":
    config = read_config('/usr/src/app/config/config.json')
    offsets = read_config('/usr/src/app/kernel_shellcode_library/offsets.json')
    c2_server = start_c2(config)
    c2_ui = start_multiprocess_cmd_line_interface(config, offsets)
    app.run(host='0.0.0.0', port=config['flask_port'])
    c2_ui.shutdown()
    stop_c2(c2_server)
