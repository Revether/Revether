import construct
import enum

LATEST_VERSION = 1
SHA1_HASH_BYTES_LENGTH = 20


class EventType(enum.Enum):
    MAKECODE = 0
    MAKEDATA = 1
    RENAMED = 2
    FUNCADD = 3
    FUNCREMOVE = 4
    SETFUNCSTART = 5
    SETFUNCEND = 6
    FUNCTAILAPPENDED = 7
    FUNCTAILDELETED = 8
    TAILOWNERCHANGED = 9
    COMMENTCHANGED = 10


EventPacket = construct.Struct(
    'version' / construct.Const(LATEST_VERSION, construct.Int8ub),
    'event_type' / construct.Enum(construct.Int8ub, EventType),
    'data' / construct.Switch(lambda ctx: int(ctx.event_type), {
        EventType.MAKECODE.value: construct.Struct('ea' / construct.Int32ub),
        EventType.MAKEDATA.value: construct.Struct(
            'ea' / construct.Int32ub,
            'flags' / construct.Int32ub,
            'size' / construct.Int32ub,
            'tid' / construct.Int32ub
            ),
        EventType.RENAMED.value: construct.Struct(
            'ea' / construct.Int32ub,
            'new_name' / construct.PascalString(construct.Int16ub, 'utf-8'),
            'local_name' / construct.Int32ub
            ),
        EventType.FUNCADD.value: construct.Struct(
            'start_ea' / construct.Int32ub,
            'end_ea' / construct.Int32ub
            ),
        EventType.FUNCREMOVE.value: construct.Struct(
            'start_ea' / construct.Int32ub,
            ),
        EventType.SETFUNCSTART.value: construct.Struct(
            'start_ea' / construct.Int32ub,
            'new_start_ea' / construct.Int32ub
            ),
        EventType.SETFUNCEND.value: construct.Struct(
            'start_ea' / construct.Int32ub,
            ),
        EventType.FUNCTAILAPPENDED.value: construct.Struct(
            'func_start_ea' / construct.Int32ub,
            'tail_start_ea' / construct.Int32ub,
            'tail_end_ea' / construct.Int32ub
            ),
        EventType.FUNCTAILDELETED.value: construct.Struct(
            'func_start_ea' / construct.Int32ub,
            'tail_ea' / construct.Int32ub
            ),
        EventType.TAILOWNERCHANGED.value: construct.Struct(
            'tail_ea' / construct.Int32ub,
            'owner_func' / construct.Int32ub
            ),
        EventType.COMMENTCHANGED.value: construct.Struct(
            'ea' / construct.Int32ub,
            'comment' / construct.PascalString(construct.Int16ub, 'utf-8'),
            'repeatable' / construct.Int32ub
            ),
    })
)


ConnectionPacket = construct.Struct(
    # The version being validated automatically
    'version' / construct.Const(LATEST_VERSION, construct.Int8ub),
    'idb_name' / construct.PascalString(construct.Int16ub, 'utf-8'),
    'idb_hash' / construct.Bytes(SHA1_HASH_BYTES_LENGTH),
)


def create_event_packet(event_type, *args, **kwargs):
    return EventPacket.build(dict(
        event_type=event_type,
        data=dict(**kwargs)
    ))


def create_connection_packet(idb_name, idb_hash):
    return ConnectionPacket.build(dict(
        idb_name=idb_name,
        idb_hash=idb_hash
    ))
