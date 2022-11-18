'''
Triggers used to indicate when a packets sequence must be transmitted.
'''
from whad.exceptions import TriggerNotAssociated, InvalidTriggerPattern
from whad.helpers import scapy_packet_to_pattern
from scapy.packet import Packet

class Trigger:
    def __init__(self):
        self._connector = None
        self._triggered = False

    @property
    def triggered(self):
        return self._triggered

    @triggered.setter
    def triggered(self, triggered):
        self._connector = triggered

    @property
    def connector(self):
        return self._connector

    @connector.setter
    def connector(self, connector):
        self._connector = connector

    def to_message(self):
        return None

class ManualTrigger(Trigger):
    def __init__(self):
        super().__init__()

    def trigger(self):
        if self._connector is None:
            raise TriggerNotAssociated()
        self._connector.trigger()

class ConnectionEventTrigger(Trigger):
    def __init__(self, connection_event):
        super().__init__()
        self._connection_event = connection_event

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
            scapy_packet_to_pattern(packet, selected_fields, selected_layers)

        else:
            raise InvalidTriggerPattern()

    @property
    def pattern(self):
        return self._pattern

    @property
    def mask(self):
        return self._mask

    @property
    def offset(self):
        return self._offset

from scapy.all import *
t = ReceptionTrigger(packet=BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"ABCD"),selected_fields=("len", "value"))#, selected_layers=(L2CAP_Hdr,))
print(t.pattern, t.mask, t.offset)
