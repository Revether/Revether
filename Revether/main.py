import click
import logging

from revether import logger
from revether.server import server


@click.command()
@click.option('--host', default='127.0.0.1', help='Host to listen on')
@click.option('--port', default='5565', help='Port to listen on')
def main(host, port):
    server_logger = logger.initiate_logger(None, __name__, logging.DEBUG)
    with server.RevetherServer(server_logger, host, int(port)):
        pass


if __name__ == "__main__":
    main()
