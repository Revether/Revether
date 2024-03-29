import os
import hashlib
import time
import contextlib
import socket
import io

from revether_server.client import Client
from revether_server.config import Configuration
from revether_common.net.packets import (
    create_connection_packet, create_event_packet, EventType, PacketType,
    create_request_packet, RequestType)


HOST = '127.0.0.1'
PORT = 5565
DUMMY_IDB_NAME = u'dummy_idb'
IDB_UPLOAD_SIZE = 5 * 1024 * 1024
IDB_UPLOAD_CHUNK_SIZE = 16384


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
    with revether_client(DUMMY_IDB_NAME) as c1:
        with revether_client(DUMMY_IDB_NAME) as c2:
            # TODO: We should use the actual IDBHooks & network manager classes
            # TODO: But it will require us to write mock qt_socket
            # TODO: And also seperate network_manager from idc and stuff.
            wait_for(lambda: len(revether_server.clients) == 2, 5)

            event_packet = create_event_packet(EventType.MAKECODE.value, ea=0x123456)
            c1.send_pkt(event_packet)

            pkt_type, body = c2.get_packet()

            assert pkt_type == PacketType.EVENT.value
            assert int(body.event_type) == EventType.MAKECODE.value
            assert body.data.ea == 0x123456


def test_server_upload_idb(revether_server):
    with revether_client(DUMMY_IDB_NAME) as client:
        wait_for(lambda: len(revether_server.clients) == 1, 5)

        data = io.BytesIO()
        with open('/dev/urandom', 'rb') as f:
            data.write(f.read(IDB_UPLOAD_SIZE))

        data.seek(0)
        send_hash = hashlib.sha1(data.read()).digest()
        client.send_pkt(create_request_packet(
            RequestType.UPLOAD_IDB_START.value,
            idb_name=DUMMY_IDB_NAME,
            idb_hash=send_hash,
            idb_size=data.tell()
        ))

        # Assuming IDB_UPLOAD_SIZE % IDB_UPLOAD_CHUNK_SIZE == 0
        sent_size = 0
        data.seek(0)
        while sent_size != IDB_UPLOAD_SIZE:
            client.send_pkt(create_request_packet(
                RequestType.IDB_CHUNK.value,
                data=data.read(IDB_UPLOAD_CHUNK_SIZE)
            ))
            sent_size += IDB_UPLOAD_CHUNK_SIZE

        client.send_pkt(create_request_packet(
            RequestType.IDB_END.value
        ))

        file_name = os.path.join(Configuration.get_idbs_dir(), DUMMY_IDB_NAME)
        wait_for(lambda: os.path.isfile(file_name), 5)

        with open(file_name, 'rb') as f:
            recv_data = f.read()

        os.remove(file_name)

        assert len(recv_data) == IDB_UPLOAD_SIZE
        assert hashlib.sha1(recv_data).digest() == send_hash


def test_server_download_idb(revether_server):
    with revether_client(DUMMY_IDB_NAME) as client:
        wait_for(lambda: len(revether_server.clients) == 1, 5)

        with open("/dev/urandom", 'rb') as f:
            dummy_idb_data = f.read(IDB_UPLOAD_SIZE)

        dummy_idb_path = os.path.join(Configuration.get_idbs_dir(), DUMMY_IDB_NAME)
        with open(dummy_idb_path, 'wb') as f:
            f.write(dummy_idb_data)

        client.send_pkt(create_request_packet(
            RequestType.DOWNLOAD_IDB_START.value,
            idb_name=DUMMY_IDB_NAME
        ))

        recvd_size = 0
        total_data = ""
        while recvd_size < IDB_UPLOAD_SIZE:
            pkt_type, data_chunk = client.get_packet()

            assert pkt_type == PacketType.REQUEST.value
            assert int(data_chunk.request_type) == RequestType.IDB_CHUNK.value
            assert len(data_chunk.data.data) == IDB_UPLOAD_CHUNK_SIZE

            total_data += data_chunk.data.data
            recvd_size += len(data_chunk.data.data)

        os.remove(dummy_idb_path)

        assert len(total_data) == IDB_UPLOAD_SIZE
        assert hashlib.sha1(dummy_idb_data).digest() == hashlib.sha1(total_data).digest()
