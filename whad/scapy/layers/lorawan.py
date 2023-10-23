"""LoRaWAN packets rework
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import StrFixedLenField, BitField, BitEnumField, FCSField, \
    XLEShortField, XLEIntField, LEThreeBytesField, ByteField, LEShortField, \
    StrLenField, XByteField
from scapy.config import conf
from struct import pack, unpack

from whad.helpers import bits_to_bytes, bytes_to_bits, bitwise_xor

class EUIField(StrFixedLenField):
    """LoRaWAN Extended Unique Identifier
    """

    def __init__(self, name, default):
        super().__init__(name, default, length=8)

    def i2h(self, pkt, x):
        return ":".join(["{:02x}".format(i) for i in x[::-1]])

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)
    
    def any2i(self, pkt, x):
        if isinstance(x, str):
            x = bytes.fromhex(x.replace(":",""))[::-1]
        return x

class PHYPayload(Packet):
    """LoRaWAN 1.0 & 1.1 PHYPayload layer
    """
    name = "LoRaWAN PHYPayload"
    fields_desc = [
        BitEnumField("mtype", 0, 3, {
            0: "JoinRequest",
            1: "JoinAccept",
            2: "UnconfirmedDataUp",
            3: "UnconfirmedDataDown",
            4: "ConfirmedDataUp",
            5: "ConfirmedDataDown",
            6: "RejoinRequest",
            7: "Proprietary"
        }),
        BitField("rfu", 0, 3),
        BitField("major", 0, 2),
        FCSField("mic", 0, fmt="<I")
    ]

class JoinRequest(Packet):
    """LoRaWAN Join Request
    """
    name = "LoRaWAN Join Request"
    fields_desc = [
        EUIField("join_eui", "00:00:00:00:00:00:00:00"),
        EUIField("dev_eui", "00:00:00:00:00:00:00:00"),
        XLEShortField("dev_nonce", 0)
    ]

class JoinAccept(Packet):
    """LoRaWAN Join Accept
    """
    name = "LoRaWAN Join Accept"
    fields_desc = [
        LEThreeBytesField("join_nonce", 0),
        LEThreeBytesField("home_netid", 0),
        XLEIntField("dev_addr", 0),
        BitField("rx2_dr", 0, 4),
        BitField("rx1_dr_offset", 0, 3),
        BitEnumField("opt_neg", 0, 1, {0:"v1.0", 1:"v1.1"}),
        ByteField("rx_delay", 0),
    ]


class MACPayloadUplink(Packet):
    """LoRaWAN Uplink MAC Payload
    """
    name = "LoRaWAN Uplink MAC Payload"
    fields_desc = [
        # FHDR fields for uplink payloads
        XLEIntField("dev_addr", 0),
        BitField("adr", 0, 1),
        BitField("adrackreq", 0, 1),
        BitField("ack", 0, 1),
        BitField("classB", 0, 1),
        BitField("fopts_len", 0, 4),
        LEShortField("fcnt", 0),
        StrLenField("fopts", b'', length_from=lambda pkt: pkt.fopts_len),

        # FPort
        XByteField("fport", 0),
    ]

class MACPayloadDownlink(Packet):
    """LoRaWAN Downlink MAC Payload
    """
    name = "LoRaWAN Downlink MAC Payload"
    fields_desc = [
        XLEIntField("dev_addr", 0),
        BitField("adr", 0, 1),
        BitField("adrackreq", 0, 1),
        BitField("ack", 0, 1),
        BitField("classB", 0, 1),
        BitField("fopts_len", 0, 4),
        LEShortField("fcnt", 0),
        StrLenField("fopts", b'', length_from=lambda pkt: pkt.fopts_len),
        
        # FPort
        XByteField("fport", 0),
    ]


class CFList(Packet):
    """LoRaWAN CFList
    """
    name = "LoRaWAN CFList"


bind_layers(PHYPayload, JoinRequest, mtype=0)
bind_layers(PHYPayload, JoinAccept, mtype=1)
bind_layers(JoinAccept, CFList)
bind_layers(PHYPayload, MACPayloadUplink, mtype=2)
bind_layers(PHYPayload, MACPayloadDownlink, mtype=3)
bind_layers(PHYPayload, MACPayloadUplink, mtype=4)
bind_layers(PHYPayload, MACPayloadDownlink, mtype=5)