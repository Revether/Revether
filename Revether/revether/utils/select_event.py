import os


class SelectableEvent(object):
    def __init__(self):
        read_fd, write_fd = os.pipe()

        self._read_end = os.fdopen(read_fd)
        self._write_end = os.fdopen(write_fd)

    def fileno(self):
        return self.read_fd.fileno()

    def set(self):
        # It doesn't really matter what we are writing to the pipe,
        # as long, something gets written
        return self._write_end.write(' ')
