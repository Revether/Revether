import logging
import socket
import select
import threading

import client

# from ..utils.net import set_socket_keepalive
from ..utils.select_event import SelectableEvent


class RevetherServer(object):
    LISTEN_BACKLOG = 5

    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.__server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.__stop_event = SelectableEvent()
        self.__connected_clients = []
        self.__server_thread = None

        logging.basicConfig()
        self.__logger = logging.getLogger(__name__)
        self.__logger.setLevel(logging.INFO)

    def start(self, block=False):
        """
        Start the listening and processing of the server

        Args:
            block (bool): Should this function block. Default is False.
                          When False, new thread will be created.
        """
        self.__logger.info("Starting the server on {}:{}".format(self.host, self.port))
        self.__server_socket.bind((self.host, self.port))
        self.__server_socket.listen(RevetherServer.LISTEN_BACKLOG)

        self.__logger.info("Listening...")

        if block:
            self.__server_loop()
        else:
            self.__server_thread = threading.Thread(target=self.__server_loop)
            self.__server_thread.start()

    def stop(self):
        """
        Stop the server.
        If the server started with block=False, it will also kill the thread.
        All connections with the client will be closed.
        """
        self.__stop_event.set()

        if self.__server_thread:
            self.__server_thread.join()

        self.__close_connection_with_clients()
        self.__server_socket.close()

    def __enter__(self):
        self.start(block=True)

    def __exit__(self):
        self.stop()

    def __server_loop(self):
        """
        Main server loop. Handles incoming events from clients.
        Also responsible for handshake with clients.
        """
        while True:
            read_ready, _, _ = select.select(
                [self.__server_socket, self.__stop_event] + self.__connected_clients,
                [],
                []
            )

            if self.__stop_event in read_ready:
                break

            # Accept new client that connects to the server
            if self.__server_socket in read_ready:
                self.__accept_new_client()
                read_ready.remove(self.__server_socket)

            self.__handle_ready_clients(read_ready)

    def __accept_new_client(self):
        """
            Accept new client that connects to server.
            Note:
                Function is blocking, should be called after selected the server socket.
        """
        client_socket, client_addr = self.__server_socket.accept()
        new_client = client.Client(client_socket)
        self.__logger.info("Accepted new client from {}".format(client_addr))
        self.__connected_clients.append(new_client)

    def __handle_ready_clients(self, ready_clients):
        """
        Handle clients that ready (has new data).
        Receives the events, and broadcasts them.

        Args:
            ready_clients (list): list of the ready clients.
        """
        for current_client in ready_clients:
            if not current_client.ready:
                try:
                    current_client.handshake()
                    self.__logger.info("Handshake complete, idb_name: {}, idb_hash: {}".format(
                        current_client.idb_name, current_client.idb_hash.encode('hex')))
                except Exception as e:  # Catch only the right exceptions?
                    self.__logger.error("Error while handshake with client: {}".format(e))
                    self.__logger.exception(e)
                    self.__close_connection_with_client(current_client)

                continue

            event = current_client.get_event()
            self.__logger.debug("Got event: {}".format(event))

            # Save it to DB?

            # Broadcast the event
            self.__broadcast_events([event])

    def __close_connection_with_client(self, current_client):
        """
        Close the connection with client.
        Removes the client from the client list.

        Args:
            current_client (Client): The client to close.
        """
        self.__connected_clients.remove(current_client)
        current_client.close_connection()

    def __close_connection_with_clients(self):
        """
        Close connection with all the clients.
        """
        for current_client in self.__connected_clients:
            self.__close_connection_with_client(current_client)

    def __broadcast_events(self, events):
        """
        Broadcast a new events to all clients.
        TODO: Don't broadcast to the client that sent the event.

        Args:
            events (list): The events to broadcast.
        """
        for current_client in self.__connected_clients:
            current_client.update_about_changes(events)
