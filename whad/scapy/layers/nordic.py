from scapy.all import *
from scapy.layers.bluetooth4LE import BTLE

class LEMACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(x)[::-1]
    def m2i(self, pkt, x):
        return str2mac(x[::-1])
    def any2i(self, pkt, x):
        if type(x) is str and len(x) == 6:
            x = self.m2i(pkt, x)
        return x
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x
    def randval(self):
        return RandMAC()

class NordicBLE(Packet):
    name="Nordic BLE"
    fields_desc = [
            XByteField('board_id',-1),
            ByteField('proto_version', -1),
            LEShortField('pkt_counter', -1),
            LEShortField('pkt_id', -1),
            ShortField('pkt_len',-1),
            XByteField('flags', 0),
            ByteField('channel', 0),
            ByteField('rssi', 0),
            ShortField('event_counter', 0),
            LEIntField('timestamp',0),
        ]

    def mysummary(self):
        return self.sprintf("NordicBLE channel=%channel%")

bind_layers( NordicBLE, BTLE,)
conf.l2types.register(272, NordicBLE)
