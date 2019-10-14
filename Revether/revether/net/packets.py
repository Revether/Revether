import construct
import enum
import json

from ..utils.unicoder import Unicoder

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
    RANGECOMMENTCHANGED = 11
    EXTRACOMMENTCHANGED = 12
    OPTYPECHANGED = 13


class PacketType(enum.Enum):
    CONNECTION = 0
    EVENT = 1
    REQUEST = 2


class RequestType(enum.Enum):
    UPLOAD_IDB_START = 0
    DOWNLOAD_IDB_START = 1

    IDB_CHUNK = 2
    IDB_END = 3

    UPLOAD_IDB_SUCCESS = 4
    UPLOAD_IDB_INVALID_SIZE = 5
    UPLOAD_IDB_INVALID_HASH = 6

    GET_ALL_IDBS = 7
    GET_ALL_IDBS_RESPONSE = 8


class DictAdapter(construct.Adapter):
    def _decode(self, obj, context, path):
        return json.loads(Unicoder.encode(obj))

    def _encode(self, obj, context, path):
        return Unicoder.decode(json.dumps(obj))


ConnectionPacket = construct.Struct(
    'idb_name' / construct.PascalString(construct.Int16ub, 'utf-8'),
    'idb_hash' / construct.Bytes(SHA1_HASH_BYTES_LENGTH),
)

EventPacket = construct.Struct(
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
            'repeatable' / construct.Flag
            ),
        EventType.RANGECOMMENTCHANGED.value: construct.Struct(
            'kind' / construct.Int32ub,
            'start_ea' / construct.Int32ub,
            'comment' / construct.PascalString(construct.Int16ub, 'utf-8'),
            'repeatable' / construct.Flag
        ),
        EventType.EXTRACOMMENTCHANGED.value: construct.Struct(
            'ea' / construct.Int32ub,
            'line_idx' / construct.Int32ub,
            'comment' / construct.PascalString(construct.Int16ub, 'utf-8')
        ),
        EventType.OPTYPECHANGED.value: construct.Struct(
            'ea' / construct.Int32ub,
            'n' / construct.Int32ub,
            'op' / construct.PascalString(construct.Int16ub, 'utf-8'),
            'extra' / DictAdapter(construct.PascalString(construct.Int16ub, 'utf-8'))
        ),
    })
)

RequestPacket = construct.Struct(
    'request_type' / construct.Enum(construct.Int8ub, RequestType),
    'data' / construct.Switch(lambda ctx: int(ctx.request_type), {
        RequestType.UPLOAD_IDB_START.value: construct.Struct(
            'idb_name' / construct.PascalString(construct.Int16ub, 'utf-8'),
            'idb_hash' / construct.Bytes(SHA1_HASH_BYTES_LENGTH),
            'idb_size' / construct.Int32ub
        ),
        RequestType.IDB_CHUNK.value: construct.Struct(
            'data' / construct.Prefixed(construct.VarInt, construct.Compressed(construct.GreedyBytes, 'zlib'))
        ),
        RequestType.DOWNLOAD_IDB_START.value: construct.Struct(
            'idb_name' / construct.PascalString(construct.Int16ub, 'utf-8')
        ),
        RequestType.GET_ALL_IDBS_RESPONSE.value: construct.GreedyRange(
            construct.Struct(
                "name" / construct.PascalString(construct.VarInt, "utf-8"),
                "size" / construct.Int32ub
            )
        )
    })
)

RevetherPacket = construct.Struct(
    'header' / construct.Struct(
        'version' / construct.Const(LATEST_VERSION, construct.Int8ub),
        'type' / construct.Enum(construct.Int8ub, PacketType),
    ),
    'body' / construct.Switch(lambda ctx: int(ctx.header.type), {
        PacketType.EVENT.value: EventPacket,
        PacketType.CONNECTION.value: ConnectionPacket,
        PacketType.REQUEST.value: RequestPacket
    })
)


def create_event_packet(event_type, *args, **kwargs):
    return RevetherPacket.build(dict(
        header=dict(
            type=PacketType.EVENT.value,
        ),
        body=dict(
            event_type=event_type,
            data=dict(**kwargs)
        )
    ))


def wrap_event(event_packet):
    return RevetherPacket.build(dict(
        header=dict(
            type=PacketType.EVENT.value,
        ),
        body=event_packet
    ))


def create_connection_packet(idb_name, idb_hash):
    return RevetherPacket.build(dict(
        header=dict(
            type=PacketType.CONNECTION.value
        ),
        body=dict(
            idb_name=idb_name,
            idb_hash=idb_hash
        )
    ))


def create_request_packet(request_type, *args, **kwargs):
    return RevetherPacket.build(dict(
        header=dict(
            type=PacketType.REQUEST.value
        ),
        body=dict(
            request_type=request_type,
            data=dict(**kwargs)
        )
    ))
