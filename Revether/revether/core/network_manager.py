import socket
import os

import idc

from ..utils.net import set_socket_keepalive
from ..net.packets import create_connection_packet

class NetworkManager(object):
    def __init__(self):
        self._socket = socket.socket()
        self._connected = False

    @property
    def connected(self):
        return self._connected

    def connect(self, ip, port):
        if self._connected:
            return

        self._socket.connect((ip, port))
        set_socket_keepalive(self._socket)

        pkt = create_connection_packet(os.path.split(idc.get_idb_path())[-1], 123)
        self.send(pkt)

        self._connected = True

    def disconnect(self):
        self._socket.close()
        self._connected = False
        self._socket = socket.socket()

    def send(self, data):
        self._socket.send(data)