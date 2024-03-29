import construct
import job
from revether_common.net.packets import RevetherPacket
from revether_common.utils.net import recvall


class ClientSocket(object):
    def __init__(self, sock):
        self.__sock = sock

    def read(self, size):
        return recvall(self.__sock, size)


class Client(object):
    def __init__(self, sock, addr):
        self.__sock = sock
        self.addr = addr

        self.idb_hash = None
        self.idb_name = None

        # The client and server handshaked
        self.ready = False

        # Used to **download** files from the client.
        # The client is uploading to the server
        self.downloader = None

        self.jobs = []

    def fileno(self):
        return self.__sock.fileno()

    @property
    def socket(self):
        return self.__sock

    def set_idb_hash(self, idb_hash):
        self.idb_hash = idb_hash

    def needs_update(self, updated_hash):
        return updated_hash != self.idb_hash

    def update_about_changes(self, events):
        for event in events:
            self.__sock.send(event)

    def get_packet(self):
        pkt = RevetherPacket.parse_stream(ClientSocket(self.__sock))
        return int(pkt.header.type), pkt.body

    def close_connection(self):
        self.__sock.close()

    def handshake(self):
        try:
            connection_packet = RevetherPacket.parse_stream(ClientSocket(self.__sock))
        except construct.ConstructError:
            raise EOFError

        self.__set_idb(
            connection_packet.body.idb_name,
            connection_packet.body.idb_hash
        )
        self.ready = True

    def __set_idb(self, idb_name, idb_hash):
        self.idb_name = idb_name
        self.idb_hash = idb_hash

    def send_pkt(self, pkt):
        self.__sock.sendall(pkt)

    def add_job(self, client_job):
        # Check that the passed job is valid
        assert isinstance(client_job, job.Job)
        self.jobs.append(client_job)
        client_job.start()
