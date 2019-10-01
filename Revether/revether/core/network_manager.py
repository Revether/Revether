import socket
import os

import idc

import logging
logger = logging.getLogger('RevetherLogger')
from ..utils.net import set_socket_keepalive
from ..net.packets import create_connection_packet, create_event_packet

class NetworkManager(object):
    def __init__(self):
        self._socket = socket.socket()
        self._connected = False

    @property
    def connected(self):
        return self._connected

    def send_event(self, event_type, *args, **kwargs):
        pkt = create_event_packet(event_type.value, *args, **kwargs)
        logger.debug(pkt.encode('hex'))
        self.send(pkt)

    def connect(self, ip, port):
        if self._connected:
            return

        self._socket.connect((ip, port))
        set_socket_keepalive(self._socket)

        if idc.get_idb_path():
            path = unicode(os.path.split(idc.get_idb_path())[-1])
        else:
            path = u'no_idb'

        pkt = create_connection_packet(path, '\x00'*20)
        self.send(pkt)

        self._connected = True

    def disconnect(self):
        self._socket.close()
        self._connected = False
        self._socket = socket.socket()

    def send(self, data):
        self._socket.send(data)