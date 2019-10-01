from ..net.packets import EventPacket, ConnectionPacket, LATEST_VERSION


class Client(object):
    def __init__(self, sock):
        self.__sock = sock

        self.idb_hash = None
        self.idb_name = None

        # The client and server handshaked
        self.ready = False

    def fileno(self):
        return self.__sock.fileno()

    def set_idb_hash(self, idb_hash):
        self.idb_hash = idb_hash

    def needs_update(self, updated_hash):
        return updated_hash != self.idb_hash

    def update_about_changes(self, events):
        for event in events:
            self.__sock.send(event)

    def get_event(self):
        return EventPacket.parse_stream(self.__sock)

    def close_connection(self):
        self.__sock.close()

    def handshake(self):
        connection_packet = ConnectionPacket.parse_stream(self.__sock)
        self.__set_idb(connection_packet.idb_name, connection_packet.idb_hash)
        self.ready = True

    def __set_idb(self, idb_name, idb_hash):
        self.idb_name = idb_name
        self.idb_hash = idb_hash
