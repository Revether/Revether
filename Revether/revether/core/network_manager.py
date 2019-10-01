import socket

from ..utils.net import set_socket_keepalive

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
        self._connected = True

    def disconnect(self):
        self._socket.close()
        self._connected = False
        self._socket = socket.socket()

    def send(self, data):
        self._socket.send(data)