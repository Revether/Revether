import time
import contextlib
import socket

from revether_server.client import Client
from revether_common.net.packets import (
    create_connection_packet, create_event_packet, EventType, PacketType)

HOST = '127.0.0.1'
PORT = 5565
DUMMPY_IDB_NAME = u'dummy_idb'


@contextlib.contextmanager
def revether_client(idb_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s.connect((HOST, PORT))
    pkt = create_connection_packet(idb_name, '\x00'*20)
    s.sendall(pkt)
    c = Client(s, "dummy_client")

    try:
        yield c
    finally:
        c.close_connection()


def wait_for(f, timeout):
    time_elapsed = 0
    while time_elapsed < timeout:
        if f():
            return time_elapsed
        else:
            time.sleep(0.1)
            time_elapsed += 0.1

    raise RuntimeError


def test_server_event_handling(revether_server):
    with revether_client(DUMMPY_IDB_NAME) as c1:
        with revether_client(DUMMPY_IDB_NAME) as c2:
            # TODO: We should use the actual IDBHooks & network manager classes
            # TODO: But it will require us to write mock qt_socket
            # TODO: And also seperate network_manager from idc and stuff.
            wait_for(lambda: len(revether_server.clients) == 2, 5)
            print(len(revether_server.clients))

            event_packet = create_event_packet(EventType.MAKECODE.value, ea=0x123456)
            c1.send_pkt(event_packet)

            pkt_type, body = c2.get_packet()

            assert pkt_type == PacketType.EVENT.value
            assert int(body.event_type) == EventType.MAKECODE.value
            assert body.data.ea == 0x123456
