class Unicoder(object):
    @staticmethod
    def decode(s):
        if isinstance(s, str):
            return s
        return s.decode('raw_unicode_escape')

    @staticmethod
    def encode(s):
        if isinstance(s, unicode):
            return s
        return s.encode('raw_unicode_escape')
