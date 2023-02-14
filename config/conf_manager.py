import json


def read_config(filename="/usr/src/app/config/config.json"):
    with open(filename, 'r') as f:
        conf = json.load(f)
    return conf


def pretty_print_config(config):
    print(json.dumps(config, sort_keys=True, indent=4, default=str))
