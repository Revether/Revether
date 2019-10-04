import functools
import os

import downloader

from exceptions import FileHashMismatchError, FileSizeMismatchError
from ..net.packets import RequestType


# exists means if downloader should exists or not
def validate_downloader(func, exists=True):
    @functools.wraps(func)
    def wrap_method(self, client, *args, **kwargs):
        if not client.downloader and exists:
            self.__logger.warning("Client {} sent an upload data, but no downloader available".format(client.addr))
        elif client.downloader and not exists:
            self.__logger.warning("Client {} sent an upload request but already uploading".format(client.addr))
            return

        func(client, *args, **kwargs)

    return wrap_method


class Requests(object):
    def __init__(self, logger):
        self.__logger = logger

        self.__requests_handlers = {
            RequestType.UPLOAD_IDB_START: self.__handle_upload_idb_start,
            RequestType.UPLOAD_IDB_CHUNK: self.__handle_upload_idb_chunk,
            RequestType.UPLOAD_IDB_END: self.__handle_upload_idb_end,
        }

    def dispatch_request_handler(self, client, request_type, *args, **kwargs):
        try:
            self.__requests_handlers[request_type](client, *args, **kwargs)
        except KeyError:
            self.__logger.error("Invalid request type {} sent from client {}".format(request_type, client.addr))

    @validate_downloader(exists=False)
    def __handle_upload_idb_start(self, client, idb_name, idb_hash, idb_size):
        self.__logger.info("Client {} sent an upload request, starting the upload".format(client.addr))

        # TODO: Make the path and name configurable
        local_file_path = os.path.join('C:\\Revether\\idbs', "{}_{}".format(idb_name, idb_hash))
        client.downloader = downloader.Downloader(self.__logger, local_file_path, idb_name, idb_hash, idb_size)

    @validate_downloader
    def __handle_upload_idb_chunk(self, client, data):
        client.downloader.add_chunk(data)

    @validate_downloader
    def __handle_upload_idb_end(self, client):
        try:
            client.downloader.finish()
        except (FileSizeMismatchError, FileSizeMismatchError) as e:
            self.__logger.error("Error while downloading file: {}".format(e))
            raise
        finally:
            client.downloader = None

        self.__logger.info("Finished downloading {} from client {}".format(client.downloader.file_name, client.addr))