import io
import hashlib

from exceptions import FileHashMismatchError, FileSizeMismatchError
from revether_common.net.packets import RequestType


class Downloader(object):
    def __init__(self, logger, local_file_path, file_name, file_hash, file_size):
        self.__logger = logger
        self.file_name = file_name
        self.file_hash = file_hash
        self.file_size = file_size
        self.local_file_path = local_file_path

        self.__size_downloaded = 0
        self.__data = io.BytesIO()

        self.__chunks = 0

        self.finished = False

    def add_chunk(self, chunk_data):
        """
        Add chunk of data to the final file.
        Usually call this funcion when a new chunk arrived from the socket

        Args:
            chunk_data (str): The chunk
        """
        self.__data.write(chunk_data)
        self.__size_downloaded += len(chunk_data)
        self.__chunks += 1
        self.__logger.debug(
            "Adding chunk #{} of size {}, client sent {}".format(
                self.__chunks, len(chunk_data), self.__size_downloaded))

    def finish(self):
        """
        Finish the file download. Validates the size and the hash of the file.
        Also saves it to the local_file_path passed on the init

        Note:
            Can throw FileSizeMismatchError or FileHashMismatchError
        """
        self.__data.seek(0)
        file_hash = hashlib.sha1(self.__data.read()).digest()
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
        with open(self.local_file_path, 'wb') as f:
            f.write(self.__data.read())
