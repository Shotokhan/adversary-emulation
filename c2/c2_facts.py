from typing import List, Union
from c2.c2_server import ConnectionStorage, InvalidConnUUID


class NotExistentFact(Exception):
    pass


class ReadOnlyFactError(Exception):
    pass


class FactsStorage:
    def __init__(self, connectionStorage: ConnectionStorage, connUuid: str):
        self.connectionStorage = connectionStorage
        self.connUuid = connUuid

    def getConn(self):
        # just a short-hand
        try:
            return self.connectionStorage.connections[self.connUuid]
        except KeyError:
            raise InvalidConnUUID

    def getFact(self, fact_name: str):
        self.connectionStorage.reload()
        if fact_name not in self.getConn()['facts']:
            raise NotExistentFact
        else:
            return self.getConn()['facts'][fact_name]

    def setFact(self, fact_name: str, fact_value: Union[str, List[str]], overwrite=True):
        self.connectionStorage.start_sync()
        if fact_name in self.getConn()['facts'] and not overwrite:
            self.connectionStorage.end_sync()
            raise ReadOnlyFactError
        else:
            self.getConn()['facts'][fact_name] = fact_value
        self.connectionStorage.end_sync()

    def enrichFact(self, fact_name: str, fact_value: Union[str, List[str]], overwrite=True):
        self.connectionStorage.reload()
        self.connectionStorage.start_sync()
        if fact_name in self.getConn()['facts'] and not overwrite:
            self.connectionStorage.end_sync()
            raise ReadOnlyFactError
        else:
            try:
                previous_fact_value = self.getConn()['facts'][fact_name]
            except KeyError:
                previous_fact_value = []
            if not isinstance(previous_fact_value, List):
                previous_fact_value = [previous_fact_value]
            if not isinstance(fact_value, List):
                fact_value = [fact_value]
            new_fact_value = previous_fact_value + fact_value
            self.getConn()['facts'][fact_name] = new_fact_value
        self.connectionStorage.end_sync()
