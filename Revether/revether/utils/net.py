import socket


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
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, fail_count)