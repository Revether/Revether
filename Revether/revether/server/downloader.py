import io
import hashlib

from exceptions import FileHashMismatchError, FileSizeMismatchError
from ..net.packet import RequestType


class Downloader(object):
    def __init__(self, logger, local_file_path, file_name, file_hash, file_size):
        self.__logger = logger
        self.file_name = file_name
        self.file_hash = file_hash
        self.file_size = file_size
        self.local_file_path = local_file_path

        self.__size_downloaded = 0
        self.__data = io.BytesIO()
        self.finished = False

    def add_chunk(self, chunk_data):
        self.__data.write(chunk_data)
        self.__size_downloaded += len(chunk_data)

    def finish(self):
        self.__data.seek(0)
        file_hash = hashlib.sha1(self.__data.read()).hexdigest()
        file_size = self.__data.tell()

        if self.file_size != file_size:
            raise FileSizeMismatchError(
                "File size mismatch, got {}, expected {}".format(
                    file_size, self.file_size), RequestType.UPLOAD_IDB_INVALID_SIZE)

        if self.file_hash != file_hash:
            raise FileHashMismatchError(
                "File hash mismatch: {} != {}".format(
                    self.file_hash, file_hash, RequestType.UPLOAD_IDB_INVALID_HASH))

        self.__data.seek(0)
        with open(self.__local_file_path, 'wb') as f:
            f.write(self.__data.read())
