from ..net.packets import EventPacket


class Client(object):
    def __init__(self, sock):
        self.sock = sock
        self.idb_hash = None

    def fileno(self):
        return self.sock.fileno()

    def set_idb_hash(self, idb_hash):
        self.idb_hash = idb_hash

    def needs_update(self, updated_hash):
        return updated_hash != self.idb_hash

    def update_about_changes(self, events):
        for event in events:
            self.sock.send(event)

    def get_event(self):
        return self.sock.recv(EventPacket.parse_stream(self.sock))

    def close_connection(self):
        self.socket.close()
