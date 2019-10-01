import construct
import enum

LATEST_VERSION = 1
SHA1_HASH_BYTES_LENGTH = 20


class EventType(enum.Enum):
    MAKECODE = 0


EventPacket = construct.EmbeddedSwitch(
    construct.Struct(
        'version' / construct.Const(LATEST_VERSION, construct.Int8ub),
        'event_type' / construct.Enum(construct.Int8ub, EventType)
    ),
    construct.this.event_type,
    {
        EventType.MAKECODE.value: construct.Struct('ea' / construct.Int32ub)
    }
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
        **kwargs
    ))


def create_connection_packet(idb_name, idb_hash):
    return ConnectionPacket.build(dict(
        idb_name=idb_name,
        idb_hash=idb_hash
    ))
