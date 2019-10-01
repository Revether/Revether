import logging
import ida_idp
import ida_bytes

from ..net.packets import EventType

logger = logging.getLogger('RevetherLogger')


class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self, network_manager):
        super(IDBHooks, self).__init__()
        self._network = network_manager

    def make_code(self, insn):
        self._network.send_event(EventType.MAKECODE, ea=insn.ea)
        return 0

    def make_data(self, ea, flags, tid, size):
        self._network.send_event(
            EventType.MAKEDATA,
            ea=ea,
            flags=flags,
            size=size,
            tid=tid
            )
        return 0

    def renamed(self, ea, new_name, local_name):
        logger.debug('Inside renamed hook in ida')
        self._network.send_event(
            EventType.RENAMED,
            ea=ea,
            new_name=unicode(new_name, 'utf-8'),
            local_name=local_name
            )
        return 0

    def func_added(self, func):
        self._network.send_event(
            EventType.FUNCADD,
            start_ea=func.start_ea,
            end_ea=func.end_ea
            )
        return 0

    def deleting_func(self, func):
        self._network.send_event(
            EventType.FUNCREMOVE,
            start_ea=func.start_ea
            )
        return 0

    def set_func_start(self, func, new_start):
        self._network.send_event(
            EventType.SETFUNCSTART,
            start_ea=func.start_ea,
            new_start_ea=new_start
            )
        return 0

    def set_func_end(self, func, new_end):
        self._network.send_event(
            EventType.SETFUNCEND,
            start_ea=func.start_ea,
            new_end_ea=new_end
            )
        return 0

    def func_tail_appended(self, func, tail):
        self._network.send_event(
            EventType.FUNCTAILAPPENDED,
            func_start_ea=func.start_ea,
            tail_start_ea=tail.start_ea,
            tail_end_ea=tail.end_ea
            )
        return 0

    def func_tail_deleted(self, func, tail_ea):
        self._network.send_event(
            EventType.FUNCTAILDELETED,
            func_start_ea=func.start_ea,
            tail_ea=tail_ea
            )
        return 0

    def tail_owner_changed(self, tail, owner_func, old_owner):
        self._network.send_event(
            EventType.TAILOWNERCHANGED,
            tail_ea=tail.start_ea,
            owner_func=owner_func
            )
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        cmt = u'' if not cmt else unicode(cmt)
        self._network.send_event(
            EventType.COMMENTCHANGED,
            ea=ea,
            comment=cmt,
            repeatable=repeatable_cmt
            )
        return 0
