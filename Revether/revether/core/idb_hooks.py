import logging
import ida_idp

from ..net.packets import EventType

logger = logging.getLogger('RevetherLogger')


class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self, network_manager):
        super(IDBHooks, self).__init__()
        self._network = network_manager

    def make_code(self, insn):
        # network_manager.send_event(event_types.MAKE_CODE, insn)
        logger.debug('make_code_event happend with insn: {}'.format(insn.ea))
        self._network.send_event(EventType.MAKECODE, ea=insn.ea)
        return 0
