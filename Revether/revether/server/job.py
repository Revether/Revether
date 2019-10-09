class Job(object):
    def __init__(self, logger):
        self.__logger = logger
        self.stop_event = None
        self.error_event = None
        self.error_msg = None

    def run(self, *args, **kwargs):
        pass
