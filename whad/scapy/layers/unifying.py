from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XByteField, X3BytesField, IntField, \
    StrFixedLenField, ShortField
from struct import pack

from whad.scapy.layers.esb import ESB_Payload_Hdr, guess_payload_class_esb

class Logitech_Unifying_Hdr(Packet):
    name = "Logitech Unifying Payload"
    fields_desc = [    XByteField("dev_index",0x00),
            XByteField("frame_type",  0x00),
            XByteField("checksum",None)]

    def pre_dissect(self,s):
        calcCksum = 0xFF
        currentByte = 0
        while calcCksum+1 != s[currentByte] and currentByte < len(s) - 1:
            calcCksum = (calcCksum - s[currentByte]) & 0xFF
            currentByte += 1
        if calcCksum+1 != s[currentByte]:
            return s
        return  s[:2] + s[currentByte:currentByte+1] + s[2:currentByte] + s[currentByte+1:]

    def post_dissect(self,s):
        self.checksum = None
        return s
    def post_build(self,p,pay):
        if self.checksum is None:
            cksum = 0xFF
            for i in (p[:2] + pay):
                cksum = (cksum - i) & 0xFF
            cksum = (cksum + 1) & 0xFF
        else:
            cksum = self.checksum
        return p[:2] + pay + pack('B', cksum)


class Logitech_Wake_Up(Packet):
    name = "Logitech Wake Up Payload"
    fields_desc = [ XByteField("dev_index",0x00),
            ByteField("???(1)",  0x00),
            ByteField("???(2)",  0x00),
            X3BytesField("???(3)",  "\x01\x01\x01"),
            ByteField("unused", 13)
            ]


class Logitech_Encrypted_Keystroke_Payload(Packet):
    name = "Logitech Encrypted Keystroke Payload"
    fields_desc = [        StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7),
                ByteField("unknown",0x00),
                IntField('aes_counter',None),
                StrFixedLenField('unused', '\0\0\0\0\0\0\0', length=7)
    ]

class Logitech_Unencrypted_Keystroke_Payload(Packet):
    name = "Logitech Unencrypted Keystroke Payload"
    fields_desc = [     StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7)]

class Logitech_Multimedia_Key_Payload(Packet):
    name = "Multimedia Key Payload"
    fields_desc = [         StrFixedLenField('hid_key_scan_code', '\0\0\0\0', length=4),
                StrFixedLenField('unused','\0\0\0', length=3)]

class Logitech_Keepalive_Payload(Packet):
    name = "Logitech Keepalive Payload"
    fields_desc = [        ShortField('timeout',None)]

class Logitech_Set_Keepalive_Payload(Packet):
    name = "Logitech Set Keepalive Payload"
    fields_desc = [        ByteField("unused", None),
                ShortField('timeout',1200),
                IntField("unused_2",0x10000000)]

class Logitech_Mouse_Payload(Packet):
    name = "Logitech Mouse Payload"
    fields_desc = [    XByteField("button_mask",0x00),
            ByteField("unused",0x00),
            StrFixedLenField("movement","",length=3),
            ByteField("wheel_y",0x00),
            ByteField("wheel_x",0x00)]


def guess_payload_class_unifying(self, payload):
    if b"\x0f\x0f\x0f\x0f" == payload[:4]:
        return ESB_Ping_Request
    elif len(payload) == 0:
        return ESB_Ack_Response
    elif len(payload) >= 2 and payload[1] in (0x51,0xC2,0x40,0x4F,0xD3,0xC1,0xC3):
        return Logitech_Unifying_Hdr
    else:
        return Packet.guess_payload_class(self, payload)

def bind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_unifying

    # Logitech Unifying protocol
    bind_layers(Logitech_Unifying_Hdr, Logitech_Wake_Up,                frame_type = 0x51)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Mouse_Payload,            frame_type = 0xC2)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Keepalive_Payload,             frame_type = 0x40)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Set_Keepalive_Payload,         frame_type = 0x4F)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Encrypted_Keystroke_Payload,     frame_type = 0xD3)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Unencrypted_Keystroke_Payload,     frame_type = 0xC1)
    bind_layers(Logitech_Unifying_Hdr, Logitech_Multimedia_Key_Payload,         frame_type = 0xC3)

def unbind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_esb

    unbind_layers(Logitech_Unifying_Hdr, Logitech_Wake_Up)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Mouse_Payload)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Keepalive_Payload)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Set_Keepalive_Payload)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Encrypted_Keystroke_Payload)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Unencrypted_Keystroke_Payload)
    unbind_layers(Logitech_Unifying_Hdr, Logitech_Multimedia_Key_Payload)
