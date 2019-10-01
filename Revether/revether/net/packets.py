import construct
import enum

LATEST_VERSION = 1


class EventType(enum.Enum):
    MAKECODE = 0


EventPacket = construct.EmbeddedSwitch(
    construct.Struct(
        'version' / construct.Int8ub,
        'event_type' / construct.Enum(construct.Int8ub, EventType)
    ),
    construct.this.event_type,
    {
        EventType.MAKECODE.value: construct.Struct('ea' / construct.Int32ub)
    }
)


def create_event_packet(event_type, *args, **kwargs):
    return EventPacket.build(dict(
        version=LATEST_VERSION,
        event_type=event_type,
        **kwargs
    ))
