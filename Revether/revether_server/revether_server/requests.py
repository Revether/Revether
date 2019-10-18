import os
import functools

import downloader
import uploader

from exceptions import FileHashMismatchError, FileSizeMismatchError
from revether_common.net.packets import RequestType, create_request_packet


def parametrized(dec):
    def layer(*args, **kwargs):
        def repl(f):
            return dec(f, *args, **kwargs)
        return repl
    return layer

# exists means if downloader should exists or not
@parametrized
def validate_downloader(func, exists=True):
    @functools.wraps(func)
    def wrap_method(self, client, *args, **kwargs):
        if not client.downloader and exists:
            self.__logger.warning("Client {} sent an upload data, but no downloader available".format(client.addr))
        elif client.downloader and not exists:
            self.__logger.warning("Client {} sent an upload request but already uploading".format(client.addr))
            return

        return func(client, *args, **kwargs)

    return wrap_method


class Requests(object):
    def __init__(self, logger):
        self.__logger = logger

        # TODO: Make the path and name configurable
        # TODO: We need a global config for the server.
        # TODO: And functions that do it auto: get_idbs_dir and stuff
        self.__idbs_path = "/mnt/c/Revether/idbs/"

        self.__requests_handlers = {
            RequestType.UPLOAD_IDB_START.value: self.__handle_upload_idb_start,
            RequestType.IDB_CHUNK.value: self.__handle_upload_idb_chunk,
            RequestType.IDB_END.value: self.__handle_upload_idb_end,

            RequestType.GET_ALL_IDBS.value: self.__handle_get_all_idbs,
            RequestType.DOWNLOAD_IDB_START.value: self.__handle_download_idb_start,
        }

    def dispatch_request_handler(self, client, request_type, *args, **kwargs):
        try:
            self.__requests_handlers[request_type](client, *args, **kwargs)
        except KeyError:
            self.__logger.error("Invalid request type {} sent from client {}".format(request_type, client.addr))

    def __handle_download_idb_start(self, client, idb_name):
        # TODO: Check the idb_name exists in the idb db

        # Adds the upload job to the server
        client.add_job(uploader.Uploader(
            self.__logger, client.socket, os.path.join(self.__idbs_path, idb_name), client))

    def __handle_get_all_idbs(self, client):
        # TODO: Acutally create a list of all the idbs
        pkt = create_request_packet(
            RequestType.GET_ALL_IDBS_RESPONSE,
            [dict(name="TEST1", size=10), dict(name="TEST2", size=20)]
        )
        client.send_pkt(pkt)

    # @validate_downloader(exists=False)
    def __handle_upload_idb_start(self, client, idb_name, idb_hash, idb_size):
        self.__logger.info(
            "Client {} sent an upload request, starting the upload of file {}, size {}".format(
                client.addr, idb_name, idb_size))

        # TODO: Make the path and name configurable
        local_file_path = self.__idbs_path + "{}_{}".format(idb_name, idb_hash.encode('hex'))
        client.downloader = downloader.Downloader(self.__logger, local_file_path, idb_name, idb_hash, idb_size)

    # @validate_downloader()
    def __handle_upload_idb_chunk(self, client, data):
        client.downloader.add_chunk(data)

    # @validate_downloader()
    def __handle_upload_idb_end(self, client):
        self.__logger.info("Finished downloading {} from client {}".format(client.downloader.file_name, client.addr))

        try:
            client.downloader.finish()
        except (FileSizeMismatchError, FileHashMismatchError) as e:
            self.__logger.error("Error while downloading file: {}".format(e))
            raise
        finally:
            client.downloader = None
