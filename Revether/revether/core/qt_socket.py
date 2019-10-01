import socket

from ..net.packets import EventPacket

from PyQt5.QtCore import QObject, QSocketNotifier, QEvent, QCoreApplication
import construct

class SocketEvent(QEvent):
    """
        This Event is being sent when a new socket event is happening,
        for instance, when an incoming packet has arrived
    """

    EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

    def __init__(self):
        super(SocketEvent, self).__init__(SocketEvent.EVENT_TYPE)

class ClientSocket(object):
    def __init__(self, sock):
        self.__sock = sock

    def read(self, size):
        return self.__sock.recv(size)

class QtSocket(QObject):
    """
        This class is the glue between the communication from the server
        and the Qt event loop and by using the QSocketNotifier we can get
        notified when data is ready to be sent / received without openining
        an additional thread
    """
    def __init__(self, gotten_packet_callback, parent=None):
        super(QtSocket, self).__init__(parent)
        self._socket = None
        self._connected = False

        self._gotten_packet_callback = gotten_packet_callback

        self._incoming = []
        self._outgoing = []

    @property
    def connected(self):
        return self._connected

    def initialize_socket(self, sock):
        self._recv_notifier = QSocketNotifier(
            sock.fileno(), QSocketNotifier.Read, self
        )
        self._recv_notifier.activated.connect(self._handle_recv_ready)
        self._recv_notifier.setEnabled(True)

        self._send_notifier = QSocketNotifier(
            sock.fileno(), QSocketNotifier.Write, self
        )
        self._send_notifier.activated.connect(self._handle_send_ready)
        self._send_notifier.setEnabled(True)

        self._socket = sock
        self._connected = True

    def disconnect(self):
        if not self._socket:
            return

        self._recv_notifier.setEnabled(False)
        self._send_notifier.setEnabled(False)

        try:
            self._socket.close()
        except socket.error:
            pass

        self._socket = None
        self._connected = False

    def _handle_recv_ready(self):
        try:
            pkt = EventPacket.parse_stream(ClientSocket(self._socket))
        except construct.StreamError as e:
            self.disconnect()
            return
        self._incoming.append(pkt)

        if self._incoming:
            QCoreApplication.instance().postEvent(self, SocketEvent())

    def send_packet(self, pkt):
        self._outgoing.append(pkt)

    def _handle_send_ready(self):
        for pkt in self._outgoing:
            try:
                self._socket.send(pkt)
            except socket.error as e:
                self._logger.error(e)
                return
        self._outgoing = []

    def event(self, event):
        """
            Callback for the when a SocketEvent is happening
        """
        if isinstance(event, SocketEvent):
            self._gotten_packet_callback(self._incoming)
            self._incoming = []
            event.accept()
            return True
        else:
            event.ignore()
            return False