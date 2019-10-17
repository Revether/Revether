import pytest
import logging

from revether_server.server import RevetherServer
from revether_common import logger

HOST = '127.0.0.1'
PORT = 5565


@pytest.fixture
def revether_server():
    log = logger.initiate_logger(None, __name__, logging.DEBUG)
    server = RevetherServer(log, HOST, PORT)
    server.start()
    yield server
    server.stop()
