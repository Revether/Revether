import os
import threading
import select


class SelectableEvent(object):
    def __init__(self):
        read_fd, write_fd = os.pipe()

        self.__read_end = os.fdopen(read_fd, 'rb')
        self.__write_end = os.fdopen(write_fd, 'wb')
        self.__lock = threading.Lock()

    def fileno(self):
        with self.__lock:
            return self.__read_end.fileno()

    def set(self):
        # It doesn't really matter what we are writing to the pipe,
        # as long, something gets written
        with self.__lock:
            return self.__write_end.write('\x00')

    def is_set(self):
        with self.__lock:
            read_ready, _, _ = select.select([self.__read_end], [], [])
            return self.__read_end in read_ready

    def wait(self, timeout=0):
        read_ready, _, _ = select.select([self.__read_end], [], [], timeout=timeout)
        if read_ready:
            return True

        return False

    def clear(self):
        if not self.is_set:
            return

        with self.__lock:
            self.__read_end.read(1)
