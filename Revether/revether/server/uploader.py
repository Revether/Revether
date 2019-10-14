import select
import job


class Uploader(job.ClientJob):
    CHUNK_SIZE = 16384

    def __init__(self, logger, sock, file_path, chunk_size=CHUNK_SIZE):
        self.__sock = sock
        self.__chunk_size = chunk_size
        self.file_path = file_path

        super(Uploader, self).__init__(logger)

    def __upload(self, file):
        self.__logger.debug("Stating to upload file {}".format(self.file_path))
        while True:
            read_ready, write_ready, _ = select.select([self.event], [self.__sock], [])
            if self.event in read_ready:
                break

            if self.__sock in write_ready:
                chunk_data = file.read(self.__chunk_size)
                if not chunk_data:
                    break

                self.__sock.sendall(file.read(self.__chunk_size))
                self._logger.debug("Sent chunk of size {} of file {}".format(self.__chunk_size, self.file_path))

    def job(self, *args, **kwargs):
        with open(self.file_path, 'rb') as f:
            self.__upload(f)
