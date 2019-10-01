import click
from revether.server import server


@click.command()
@click.option('--host', default='127.0.0.1', help='Host to listen on')
@click.option('--port', default='5565', help='Port to listen on')
def main(host, port):
    revether_server = server.RevetherServer(host, int(port))

    try:
        revether_server.start(block=True)
    except KeyboardInterrupt:
        revether_server.stop()


if __name__ == "__main__":
    main()
