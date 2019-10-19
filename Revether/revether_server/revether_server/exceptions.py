class RevetherServerError(Exception):
    pass


class RevetherServerErrorWithCode(RevetherServerError):
    def __init__(self, msg, code):
        super(RevetherServerErrorWithCode, self).__init__(msg)
        self.code = code


class FileHashMismatchError(RevetherServerErrorWithCode):
    pass


class FileSizeMismatchError(RevetherServerErrorWithCode):
    pass


class IDBNotFoundError(RevetherServerErrorWithCode):
    pass
