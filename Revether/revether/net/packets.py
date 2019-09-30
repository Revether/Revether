import construct
import enum


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