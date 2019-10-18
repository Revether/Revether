import select
import job

from revether_common.net.packets import create_request_packet, RequestType


class Uploader(job.ClientJob):
    CHUNK_SIZE = 16384

    def __init__(self, logger, client, file_path, chunk_size=CHUNK_SIZE):
        self.__chunk_size = chunk_size
        self.file_path = file_path

        super(Uploader, self).__init__(logger, client)

    def __upload(self, file):
        self._logger.info("Starting to upload file {}".format(self.file_path))
        total_sent = 0

        while True:
            read_ready, write_ready, _ = select.select([self.stop_event], [self.client], [])
            if self.stop_event in read_ready:
                break

            if self.client in write_ready:
                chunk_data = file.read(self.__chunk_size)
                if not chunk_data:
                    break

                self.client.send_pkt(create_request_packet(
                    RequestType.IDB_CHUNK.value,
                    data=chunk_data
                ))
                total_sent += self.__chunk_size
                self._logger.debug("Sent chunk of file {}, total sent: {}".format(self.file_path, total_sent))

        self._logger.info("Finished uploading file {} to client {}".format(self.file_path, self.client.addr))

    def job(self, *args, **kwargs):
        with open(self.file_path, 'rb') as f:
            self.__upload(f)
