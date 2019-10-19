import click
import logging

from revether_common import logger
from revether_server.server import RevetherServer
from revether_server.config import CONFIG_FILE_PATH, Configuration


@click.command()
@click.option('--host', default='127.0.0.1', help='Host to listen on')
@click.option('--port', default='5565', help='Port to listen on')
@click.option('--config', default=CONFIG_FILE_PATH, help="The configuration file path")
def main(host, port, config):
    server_logger = logger.initiate_logger(None, __name__, logging.DEBUG)
    Configuration.init(config)

    with RevetherServer(server_logger, host, int(port)):
        pass


if __name__ == "__main__":
    main()
