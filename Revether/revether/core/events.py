import ida_ua

import logging
logger = logging.getLogger('RevetherLogger')


class Events(object):
    def __init__(self):
        pass

    def dispatch_event(self, event_type, *args, **kwargs):
        func_name = '__on_{}'.format(event_type.name.lower())
        func = getattr(self, func_name)
        func(**kwargs)

    def __on_make_code(self, ea):
        logger.debug('on_make_code_called')
        ida_ua.create_insn()
