import ida_name
import ida_bytes
import ida_funcs
import ida_ua
import ida_kernwin

import logging
logger = logging.getLogger('RevetherLogger')


class Events(object):
    def __init__(self):
        pass

    def dispatch_event(self, event_type, *args, **kwargs):
        func_name = '_on_{}'.format(str(event_type).lower())
        func = getattr(self, func_name)
        func(**kwargs)

    def _on_makecode(self, ea):
        logger.debug('on_make_code_called')
        ida_ua.create_insn(ea)

    def _on_makedata(self, ea, flags, size, tid):
        ida_bytes.create_data(ea, flags, size, tid)

    def _on_renamed(self, ea, new_name, local_name):
        flags = ida_name.SN_LOCAL if self.local_name else 0
        ida_name.set_name(ea, new_name, flags | ida_name.SN_NOWARN)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)

    def _on_funcadd(self, start_ea, end_ea):
        ida_funcs.add_func(start_ea, end_ea)

    def _on_funcremove(self, start_ea):
        ida_funcs.del_func(start_ea)

    def _on_setfuncstart(self, start_ea, new_start_ea):
        ida_funcs.set_func_start(start_ea, new_start_ea)

    def _on_setfuncend(self, start_ea, new_end_ea):
        ida_funcs.set_func_end(start_ea, new_end_ea)

    def _on_functailappended(self, func_start_ea, tail_start_ea, tail_end_ea):
        func = ida_funcs.get_func(func_start_ea)
        ida_funcs.append_func_tail(func, tail_start_ea, tail_end_ea)

    def _on_functaildeleted(self, func_start_ea, tail_ea):
        func = ida_funcs.get_func(func_start_ea)
        ida_funcs.remove_func_tail(func, tail_ea)

    def _on_tailownerchanged(self, tail_ea, owner_func):
        tail = ida_funcs.get_fchunk(tail_ea)
        ida_funcs.set_tail_owner(tail, owner_func)

    def _on_commentchanged(self, ea, comment, repeatable):
        ida_bytes.set_cmt(ea, comment, repeatable)
