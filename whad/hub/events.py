"""WHAD Generic events

These events are used to map specific WHAD (protobuf) messages to the corresponding
generic event for dispatching. Instances of these messages will be sent to connectors
to handle various events, independantly from the underlying wireless protocol.
"""
from typing import Any

class WhadEvent(object):
    """Basic WHAD event class

    This class stores a set of parameters and allow to access them as they were
    properties.
    """

    def __init__(self, **parameters):
        """Initialize the event and save the associated parameters.
        """
        self.__parameters = parameters

    def __getattr__(self, name: str) -> Any:
        """Access event parameters.
        """
        if name in self.__parameters:
            return self.__parameters[name]
        else:
            raise AttributeError
        
class ConnectionEvt(WhadEvent):
    """Connection Event.

    This event is sent whenever a connection to a remote device has succeeded.
    Parameters may vary depending the underlying wireless protocol.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class DisconnectionEvt(WhadEvent):
    """Disconnection event.

    This event is sent whenever an existing connection is terminated. Parameters
    may vary depending the underlying wireless protocol.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class HijackedEvt(WhadEvent):
    """Hijacked event.

    This event is sent when a connection has successfully been hijacked, no matter
    the protocol.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class TriggeredEvt(WhadEvent):
    """Triggered event.

    This event is sent when some prepared packets have been sent because of a
    met condition.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class JammedEvt(WhadEvent):
    """Jammed event.

    This event is sent to notify the success or failure of a jamming attack.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class SyncEvt(WhadEvent):
    """Synchronization event.

    This event is sent to noify that the hardware has successfully synchronized
    with an existing connection.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)

class DesyncEvt(WhadEvent):
    """Desynchronization event.

    This event is sent to notify that the current connection has been lost due
    to a desynchronization.
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)