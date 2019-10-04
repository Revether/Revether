import ida_name
import ida_struct
import ida_pro
import ida_enum
import ida_segment
import ida_range
import ida_lines
import ida_bytes
import ida_funcs
import ida_ua
import ida_kernwin

from ..utils.unicoder import Unicoder

import logging
logger = logging.getLogger('RevetherLogger')


class Events(object):
    def __init__(self, plugin):
        self._plugin = plugin

    def dispatch_event(self, event_type, *args, **kwargs):
        func_name = '_on_{}'.format(str(event_type).lower())
        func = getattr(self, func_name)
        self._plugin.core.uninstall_hooks()
        func(**kwargs)
        self._plugin.core.install_hooks()

    def _on_makecode(self, ea):
        logger.debug('on_make_code_called')
        ida_ua.create_insn(ea)

    def _on_makedata(self, ea, flags, size, tid):
        ida_bytes.create_data(ea, flags, size, tid)

    def _on_renamed(self, ea, new_name, local_name):
        logger.debug('Inside renamed event from server')
        flags = ida_name.SN_LOCAL if local_name else 0
        ida_name.set_name(ea, Unicoder.encode(new_name), flags | ida_name.SN_NOWARN)
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
        ida_bytes.set_cmt(ea, Unicoder.encode(comment), repeatable)

    def _on_rangecommentchanged(self, kind, start_ea, comment, repeatable):
        comment = Unicoder.encode(comment)
        if kind == ida_range.RANGE_KIND_FUNC:
            func = ida_funcs.get_func(start_ea)
            ida_funcs.set_func_cmt(func, comment, repeatable)
        elif kind == ida_range.RANGE_KIND_SEGMENT:
            segment = ida_segment.getseg(start_ea)
            ida_segment.set_segment_cmt(segment, comment, repeatable)
        else:
            raise Exception('Unsupported range kind: {}'.format(kind))

    def _on_extracommentchanged(self, ea, line_idx, comment):
        ida_lines.del_extra_cmt(ea, line_idx)
        is_previous = 1 if line_idx - 1000 < 1000 else 0
        if not comment:
            return 0
        ida_lines.add_extra_cmt(ea, is_previous, Unicoder.encode(comment))

    def _on_optypechanged(self, ea, n, op, extra):
        if op == 'hex':
            ida_bytes.op_hex(ea, n)
        if op == 'bin':
            ida_bytes.op_bin(ea, n)
        if op == 'dec':
            ida_bytes.op_dec(ea, n)
        if op == 'chr':
            ida_bytes.op_chr(ea, n)
        if op == 'oct':
            ida_bytes.op_oct(ea, n)
        if op == 'stkvar':
            ida_bytes.op_stkvar(ea, n)
        if op == 'enum':
            enum_id = ida_enum.get_enum(str(extra['ename']))
            ida_bytes.op_enum(ea, n, enum_id, extra['serial'])
        if op == 'struct':
            path_length = len(extra['spath'])
            path = ida_pro.tid_array(path_length)
            for i in range(path_length):
                sname = str(extra['spath'][i])
                path[i] = ida_struct.get_struc_id(sname)
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)
            ida_bytes.op_stroff(insn, n, path.cast(), path_length, extra['delta'])
