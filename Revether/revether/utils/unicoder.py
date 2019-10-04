class Unicoder(object):
    @staticmethod
    def decode(s):
        return s.decode('utf-8')

    @staticmethod
    def encode(s):
        if isinstance(s, unicode):
            return s
        return s.encode('utf-8')
