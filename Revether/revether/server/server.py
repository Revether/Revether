import construct
import socket
import select
import threading

import client
import requests

from ..utils.select_event import SelectableEvent
from ..net.packets import PacketType, wrap_event, create_request_packet
from exceptions import RevetherServerErrorWithCode


class RevetherServer(object):
    LISTEN_BACKLOG = 5

    def __init__(self, logger, host, port):
        self.host = host
        self.port = port

        self.__server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.__stop_event = SelectableEvent()
        self.__connected_clients = []
        self.__server_thread = None
        self.__logger = logger
        self.__requests_manager = requests.Requests(logger)

        self.__pkt_handlers = {
            PacketType.EVENT.value: self.__handle_pkt_event,
            PacketType.REQUEST.value: self.__handle_pkt_request,
        }

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
        new_client = client.Client(client_socket, client_addr)
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
                    self.__logger.debug("Handshake complete, idb_name: {}, idb_hash: {}".format(
                        current_client.idb_name, current_client.idb_hash.encode('hex')))
                except EOFError as e:  # Catch only the right exceptions?
                    self.__logger.error("Error while handshake with client: {}\n"
                                        "Closing connection".format(e))
                    self.__logger.exception(e)
                    self.__close_connection_with_client(current_client)

                continue

            try:
                pkt_type, data = current_client.get_packet()
            except construct.ConstructError as e:
                self.__logger.error("Error while trying to get data from client: {}".format(e))
                self.__logger.error("Closing connection with client: {}".format(current_client.addr))
                self.__close_connection_with_client(current_client)
                continue

            self.__handle_pkt(current_client, pkt_type, data)

    def __handle_pkt(self, current_client, pkt_type, data):
        """
        Handle a packet from client

        Args:
            current_client (Client): The client that sent the packet
            pkt_type (int): The type of packet
            data (dict): The packet data (Usually a construct body)
        """
        try:
            self.__pkt_handlers[pkt_type](current_client, data)
        except KeyError:
            self.__logger.error("Got an invalid packet type from client: {}".format(pkt_type))
        except Exception as e:
            self.__logger.error("General exception occurred while handling packet: {}".format(e))

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

    def __broadcast_events(self, from_who, events):
        """
        Broadcast a new events to all clients.

        Args:
            events (list): The events to broadcast.
            from_who (Client): The client who sent the event.
        """
        for current_client in self.__connected_clients:
            if from_who is current_client:
                continue

            # TODO: 2 different IDBs with the same name?
            if from_who.idb_name != current_client.idb_name:
                continue

            current_client.update_about_changes(events)

    def __handle_pkt_event(self, current_client, data):
        """
        Handle an event received from client.
        The handler will save the event to the DB and broadcast it to all clients.

        Args:
            current_client (Client): The client that sent the event
            data (dict): The event data (Construct packet body)
        """
        self.__logger.debug(
            "Got event from the client {}: {}".format(current_client.addr, data))

        # TODO: Save the event to the DB

        self.__broadcast_events(current_client, [wrap_event(data)])

    def __handle_pkt_request(self, current_client, data):
        """
        Handle a request from client

        Args:
            current_client (Client): The client that requested the operation
            data (dict): The body of the packet
        """
        request_type = int(data.request_type)
        del data.data['_io']

        try:
            self.__requests_manager.dispatch_request_handler(current_client, request_type, **data.data)
        except RevetherServerErrorWithCode as e:
            # Update the client about the failure
            current_client.send_pkt(create_request_packet(e.code))
