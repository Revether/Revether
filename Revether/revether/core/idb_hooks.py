import logging
import ida_idp
import ida_pro
import ida_bytes
import ida_enum
import ida_struct

from ..net.packets import EventType
from ..utils.unicoder import Unicoder

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
        self._network.send_event(
            EventType.RENAMED,
            ea=ea,
            new_name=Unicoder.decode(new_name),
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
        cmt = Unicoder.decode(u'') if not cmt else Unicoder.decode(cmt)
        self._network.send_event(
            EventType.COMMENTCHANGED,
            ea=ea,
            comment=cmt,
            repeatable=repeatable_cmt
            )
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        self._network.send_event(
            EventType.RANGECOMMENTCHANGED,
            kind=kind,
            start_ea=a.start_ea,
            comment=Unicoder.decode(cmt),
            repeatable=repeatable
        )
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._network.send_event(
            EventType.EXTRACOMMENTCHANGED,
            ea=ea,
            line_idx=line_idx,
            comment=Unicoder.decode(cmt),
        )
        return 0

    def op_type_changed(self, ea, n):
        extra = {}
        mask = ida_bytes.MS_0TYPE if not n else ida_bytes.MS_1TYPE
        flags = ida_bytes.get_full_flags(ea) & mask

        if flags == mask & ida_bytes.hex_flag():
            op = 'hex'
        elif flags == mask & ida_bytes.dec_flag():
            op = 'dec'
        elif flags == mask & ida_bytes.char_flag():
            op = 'chr'
        elif flags == mask & ida_bytes.bin_flag():
            op = 'bin'
        elif flags == mask & ida_bytes.oct_flag():
            op = 'oct'
        elif flags == mask & ida_bytes.enum_flag():
            op = 'enum'
            enum_id = ida_bytes.get_enum_id(ea, n)[0]
            enum_serial = ida_enum.get_enum_idx(enum_id)
            ename = ida_enum.get_enum_name(enum_id)
            extra['ename'] = Unicoder.decode(ename)
            extra['serial'] = enum_serial
        elif flags == mask & ida_bytes.stroff_flag():
            op = 'struct'
            path = ida_pro.tid_array(1)
            delta = ida_pro.sval_pointer()
            path_len = ida_bytes.get_stroff_path(path.cast(), delta.cast(), ea, n)
            spath = []
            for i in range(path_len):
                sname = ida_struct.get_struc_name(path[i])
                spath.append(Unicoder.decode(sname))
            extra['delta'] = delta.value()
            extra['spath'] = spath
        elif flags == mask & ida_bytes.stkvar_flag():
            op = 'stkvar'
        else:
            return 0
        self._network.send_event(
            EventType.OPTYPECHANGED,
            ea=ea,
            n=n,
            op=Unicoder.decode(op),
            extra=extra,
        )
        return 0
