from ..utils.net import set_socket_keepalive
from ..net.packets import create_connection_packet, create_event_packet
from qt_socket import QtSocket
from events import Events

import socket
import os

import idc

import logging
logger = logging.getLogger('RevetherLogger')


class NetworkManager(object):
    def __init__(self):
        self._socket = None
        self._socket_manager = QtSocket(self._dispatch)
        self._events = Events()

    @property
    def connected(self):
        return self._socket_manager.connected

    def send_event(self, event_type, *args, **kwargs):
        pkt = create_event_packet(event_type.value, *args, **kwargs)
        self._socket_manager.send_packet(pkt)

    def connect(self, ip, port):
        if self._socket_manager.connected:
            return

        self._socket = socket.socket()

        self._socket.connect((ip, port))
        set_socket_keepalive(self._socket)

        self._socket_manager.initialize_socket(self._socket)

        if idc.get_idb_path():
            path = unicode(os.path.split(idc.get_idb_path())[-1])
        else:
            path = u'no_idb'

        pkt = create_connection_packet(path, '\x00'*20)
        self._socket_manager.send_packet(pkt)

    def disconnect(self):
        self._socket_manager.disconnect()

    def send(self, data):
        self._socket.send(data)

    def _dispatch(self, incoming_pkts):
        for pkt in incoming_pkts:
            # We have to remove the inernal _io that construct
            # is inserting into the gotten pkt from the parse_stream
            del pkt.body.data['_io']
            self._events.dispatch_event(pkt.body.event_type, **pkt.body.data)
