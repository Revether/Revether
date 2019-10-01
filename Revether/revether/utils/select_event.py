import os


class SelectableEvent(object):
    def __init__(self):
        read_fd, write_fd = os.pipe()

        self.__read_end = os.fdopen(read_fd, 'rb')
        self.__write_end = os.fdopen(write_fd, 'wb')

    def fileno(self):
        return self.__read_end.fileno()

    def set(self):
        # It doesn't really matter what we are writing to the pipe,
        # as long, something gets written
        return self.__write_end.write(' ')
