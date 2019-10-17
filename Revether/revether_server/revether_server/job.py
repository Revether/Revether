import threading
from revether_common.utils.select_event import SelectableEvent


class Job(object):
    """
    Run a task (job) asynchronously.
    """

    JOB_NUMBER = 0

    def __init__(self, logger):
        self.stop_event = SelectableEvent()
        self.done_event = SelectableEvent()

        self.id = Job.JOB_NUMBER
        Job.JOB_NUMBER += 1

        self.__logger = logger
        self.__exception = None
        self.__thread = None

    def __run(self, *args, **kwargs):
        """
        Wrapper for every job.
        Runs the function `job` of the child class and waits for it to finish.
        When finishes, sets the `done_event` Event.

        On Exception, also sets the `done_event` event and sets `__exception` with the exception.
        """
        try:
            self.return_value = self.job(*args, **kwargs)
        except Exception as e:
            self.__exception = e
        finally:
            self.done_event.set()

    def fileno(self):
        return self.done_event.fileno()

    def start(self, *args, **kwargs):
        self.__thread = threading.Thread(target=self.__run, args=args, kwargs=kwargs)
        self.__thread.start()

    def finish(self, timeout=None):
        """
        Finish the job. Can be called even if the job is not actually done yet.
        In that case, we are stopping the job and returning the result

        In case of an exception in the job thread, we raise it here also.
        """
        assert self.__thread, "Job not started"

        if not self.done_event.is_set():
            self.__logger.debug("Job not finished, but finish() called. Stopping job.")
            self.stop()

        self.__thread.join(timeout)
        self.__thread = None

        if self.exception:
            raise self.__exception

        return self.return_value

    def stop(self):
        assert self.__thread, "Job not started"
        self.stop_event.set()


class ClientJob(Job):
    """
    Job that executes something that related to a client
    When the job fails (Exception is raised), the connection to the client is closed
    """
    def __init(self, logger, client):
        super(ClientJob, self).__init(logger)
        self.client = client
