import socket
import select
import threading

import client

# from ..utils.net import set_socket_keepalive
from ..utils.select_event import SelectableEvent


class RevetherServer(object):
    LISTEN_BACKLOG = 5

    def __init__(self, host, ip):
        self.host = host
        self.ip = ip

        self.__server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.__stop_event = SelectableEvent()
        self.__connected_clients = []
        self.__server_thread = None

    def start(self, block=False):
        self._server_socket.bind((self._host, self.ip))
        self._server_socket.listen(RevetherServer.LISTEN_BACKLOG)

        if block:
            self.__server_loop()
        else:
            self.__server_thread = threading.Thread(target=self.__server_loop)
            self.__server_thread.start()

    def stop(self):
        self.__stop_event.set()

        if self.__server_thread:
            self.__server_thread.join()

        self.__close_connection_with_clients()
        self._server_socket.close()

    def __enter__(self):
        self.start(block=True)

    def __server_loop(self):
        while True:
            read_ready, _, _ = select.select(
                [self._server_socket, self.__stop_event] + self.__clients,
                [],
                []
            )

            if self.__stop_event in read_ready:
                break

            # Accept new client that connects to the server
            if self._server_socket in read_ready:
                self.__accept_net_client()
                read_ready.remove(self._server_socket)

            self.__handle_ready_clients(read_ready)

    def __accept_net_client(self):
        client_socket, _ = self._server_socket.accept()
        new_client = client.Client(client_socket)
        self.__clients.append(new_client)

    def __handle_ready_clients(self, ready_clients):
        for current_client in ready_clients:
            if not current_client.ready:
                try:
                    current_client.hanshake()
                except Exception as e:  # Catch only the right exceptions?
                    # TODO: Add log about the error
                    self.__close_connection_with_client(current_client)

                continue

            event = current_client.get_event()

            # Save it to DB?

            # Broadcast the event
            self.__broadcast_event(event)

    def __close_connection_with_client(self, current_client):
        self.__clients.remove(current_client)
        current_client.close_connection()

    def __close_connection_with_clients(self):
        for current_client in self.__clients:
            current_client.close_connection()

    def __broadcast_event(self, event):
        for current_client in self.__clients:
            current_client.update_about_changes([event])
