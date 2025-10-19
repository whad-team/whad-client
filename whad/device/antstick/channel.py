from whad.hub.ant import ChannelType as WhadChannelType
from dataclasses import dataclass
from enum import IntEnum


class ChannelStatus(IntEnum):
    UNASSIGNED  = 0
    ASSIGNED    = 1
    SEARCHING   = 2
    TRACKING    = 3


class ChannelType(IntEnum):
    RECEIVE_BIDIRECTIONAL_CHANNEL           = 0x00 
    TRANSMIT_BIDIRECTIONAL_CHANNEL          = 0x10 
    RECEIVE_UNIDIRECTIONAL_CHANNEL          = 0x40
    TRANSMIT_UNIDIRECTIONAL_CHANNEL         = 0x50 
    SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL    = 0x20 
    SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL   = 0x30

    @classmethod
    def convert_from_whad_channel_type(cls, wct):
        if wct == WhadChannelType.BIDIRECTIONAL_RECEIVE_CHANNEL:
            return ChannelType.RECEIVE_BIDIRECTIONAL_CHANNEL
        elif wct == WhadChannelType.BIDIRECTIONAL_TRANSMIT_CHANNEL:
            return ChannelType.TRANSMIT_BIDIRECTIONAL_CHANNEL
        elif wct == WhadChannelType.RECEIVE_ONLY_CHANNEL:
            return ChannelType.RECEIVE_UNIDIRECTIONAL_CHANNEL
        elif wct == WhadChannelType.TRANSMIT_ONLY_CHANNEL:
            return ChannelType.TRANSMIT_UNIDIRECTIONAL_CHANNEL
        elif wct == WhadChannelType.SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL:
            return ChannelType.SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL
        elif wct == WhadChannelType.SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL:
            return ChannelType.SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL
            
@dataclass
class Channel:
    status : ChannelStatus  = ChannelStatus.UNASSIGNED
    type : ChannelType      = None
    opened : bool           = False
    assigned_network : int  = None
    period : int            = None
    device_number : int     = 0
    device_type : int       = 0
    transmission_type : int = 0
    rf_channel : int        = 57