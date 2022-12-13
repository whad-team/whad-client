'''
Triggers used to indicate when a packets sequence must be transmitted.
'''
from whad.exceptions import TriggerNotAssociated, InvalidTriggerPattern, WhadDeviceNotReady
from whad.helpers import scapy_packet_to_pattern
from scapy.packet import Packet

class Trigger:
    IDENTIFIER_COUNT = 0

    def __init__(self):
        self._connector = None
        self._triggered = False
        self._identifier = Trigger.IDENTIFIER_COUNT
        Trigger.IDENTIFIER_COUNT += 1

    @property
    def identifier(self):
        return self._identifier

    @property
    def triggered(self):
        return self._triggered

    @triggered.setter
    def triggered(self, triggered):
        self._triggered = triggered

    @property
    def connector(self):
        return self._connector

    @connector.setter
    def connector(self, connector):
        self._connector = connector

    def __del__(self):
        if self._connector is not None:
            self._connector.delete_sequence(self)


class ManualTrigger(Trigger):
    def __init__(self):
        super().__init__()

    def trigger(self):
        if self._connector is None:
            raise TriggerNotAssociated()
        self._connector.trigger(self)

class ConnectionEventTrigger(Trigger):
    def __init__(self, connection_event):
        self._connection_event = connection_event
        super().__init__()

    @property
    def connection_event(self):
        return self._connection_event

class ReceptionTrigger(Trigger):
    def __init__(self, pattern=None, mask=None, offset=None, packet=None, selected_fields=None, selected_layers=None):
        if pattern is None and packet is None:
            raise InvalidTriggerPattern()

        if pattern is not None and isinstance(pattern, bytes):
            self._pattern = pattern
            self._offset = offset if offset is not None else 0
            if mask is None:
                self._mask = bytes([0xFF for _ in range(len(self._pattern))])
            elif isinstance(mask, bytes) and len(mask) == len(self._pattern):
                self._mask = mask
            else:
                raise InvalidTriggerPattern()

        elif packet is not None and isinstance(packet, Packet):
            try:
                self._pattern, self._mask, self._offset = scapy_packet_to_pattern(packet, selected_fields, selected_layers)
            except:
                raise InvalidTriggerPattern()
        else:
            raise InvalidTriggerPattern()
        super().__init__()

    @property
    def pattern(self):
        return self._pattern

    @property
    def mask(self):
        return self._mask

    @property
    def offset(self):
        return self._offset
