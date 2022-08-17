import json


def read_config(filename="/usr/src/app/config/config.json"):
    with open(filename, 'r') as f:
        conf = json.load(f)
    return conf
