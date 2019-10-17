import os
import select


class SelectableEvent(object):
    def __init__(self):
        self.__read_fd, self.__write_fd = os.pipe()

    def fileno(self):
        return self.__read_fd

    def set(self):
        # It doesn't really matter what we are writing to the pipe,
        # as long, something gets written
        os.write(self.__write_fd, 'x')

    def is_set(self):
        return self.wait(0)

    def wait(self, timeout=None):
        read_ready, _, _ = select.select([self.__read_fd2], [], [], timeout)
        if read_ready:
            return True

        return False

    def clear(self):
        if not self.is_set:
            return

        os.read(self.__read_end, 1)
