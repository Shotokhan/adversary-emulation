def init_connection(_time, client_addr):
    return {'last_seen': _time, 'num_commands': 0, 'is_alive': True, 'client_addr': client_addr,
            'pending_cmd': False, 'facts': {}, 'cmd_uuid_to_index': {}
            }


def init_cmd_uuid_to_index_mapping(index):
    return {
        'index': index,
        'pending': True
    }
