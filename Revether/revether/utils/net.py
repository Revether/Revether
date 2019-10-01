import socket
import sys

def set_socket_keepalive(sock, idle=1, interval=3, fail_count=5):
    """
    Set socket keep-alive

    Args:
        sock: The socket to enable the keep-alive on
        idle: Idle time before the first keep-alive packet is sent
        interval: Interval between keep-alive packets
        fail_count: Count of unanswered packet before sockets marked as dead
    """

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # This code is taken from: https://github.com/andymccurdy/redis-py/blob/master/redis/connection.py
    # detect available options
    TCP_KEEPCNT = getattr(socket, 'TCP_KEEPCNT', None)
    TCP_KEEPINTVL = getattr(socket, 'TCP_KEEPINTVL', None)
    TCP_KEEPIDLE = getattr(socket, 'TCP_KEEPIDLE', None)
    TCP_KEEPALIVE = getattr(socket, 'TCP_KEEPALIVE', None)
    SIO_KEEPALIVE_VALS = getattr(socket, 'SIO_KEEPALIVE_VALS', None)
    if TCP_KEEPIDLE is None and TCP_KEEPALIVE is None \
            and sys.platform == 'darwin':
        TCP_KEEPALIVE = 0x10

    # configure
    if TCP_KEEPCNT is not None:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPCNT, fail_count)
    if TCP_KEEPINTVL is not None:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPINTVL, interval)
    if TCP_KEEPIDLE is not None:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPIDLE, idle)
    elif TCP_KEEPALIVE is not None:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, idle)
    elif SIO_KEEPALIVE_VALS is not None:
        sock.ioctl(SIO_KEEPALIVE_VALS,
                (1, idle * 1000, interval * 1000))
