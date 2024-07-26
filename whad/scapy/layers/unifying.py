from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XByteField, X3BytesField, IntField, \
    StrFixedLenField, ShortField, ByteEnumField, XShortField, XShortEnumField, \
    FieldLenField, StrLenField, StrField, SignedByteField
from struct import pack

from whad.scapy.layers.esb import ESB_Payload_Hdr, SBAddressField, ESB_Ping_Request, \
    guess_payload_class_esb

class Logitech_Unifying_Hdr(Packet):
    name = "Logitech Unifying Payload"
    fields_desc = [
        XByteField("dev_index",0x00),
        XByteField("frame_type",  0x00),
        XByteField("checksum",None)
    ]

    def pre_dissect(self,s):
        calcCksum = 0xFF
        currentByte = 0
        while calcCksum+1 != s[currentByte] and currentByte < len(s) - 1:
            calcCksum = (calcCksum - s[currentByte]) & 0xFF
            currentByte += 1
        if calcCksum+1 != s[currentByte]:
            return s
        return  s[:2] + s[currentByte:currentByte+1] + s[2:currentByte] + s[currentByte+1:]


    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def post_build(self,p,pay):
        #if self.checksum is None:
        cksum = 0xFF
        for i in (p[:2] + pay):
            cksum = (cksum - i) & 0xFF
        cksum = (cksum + 1) & 0xFF
        #else:
        #    cksum = self.checksum
        return p[:2] + pay + pack('B', cksum)


class Logitech_Wake_Up_Payload(Packet):
    name = "Logitech Wake Up Payload"
    fields_desc = [
        XByteField("dev_index",0x00),
        StrField("unknown2", b"")
    ]


class Logitech_Encrypted_Keystroke_Payload(Packet):
    name = "Logitech Encrypted Keystroke Payload"
    fields_desc = [
        StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7),
        ByteField("unknown",0x00),
        IntField('aes_counter',None),
        StrFixedLenField('unused', '\0\0\0\0\0\0\0', length=7)
    ]

class Logitech_Unencrypted_Keystroke_Payload(Packet):
    name = "Logitech Unencrypted Keystroke Payload"
    fields_desc = [
        StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7)
    ]

class Logitech_Multimedia_Key_Payload(Packet):
    name = "Multimedia Key Payload"
    fields_desc = [
        StrFixedLenField('hid_key_scan_code', '\0\0\0\0', length=4),
        StrFixedLenField('unused','\0\0\0', length=3)
    ]

class Logitech_Keepalive_Payload(Packet):
    name = "Logitech Keepalive Payload"
    fields_desc = [
        ShortField('timeout',None)
    ]

class Logitech_Set_Keepalive_Payload(Packet):
    name = "Logitech Set Keepalive Payload"
    fields_desc = [
        ByteField("unused", None),
        ShortField('timeout',1200),
        IntField("unused_2",None)
    ]

class Logitech_Mouse_Payload(Packet):
    name = "Logitech Mouse Payload"
    fields_desc = [
        XByteField("button_mask",0x00),
        ByteField("unused",0x00),
        StrFixedLenField("movement","",length=3),
        SignedByteField("wheel_y",0x00),
        SignedByteField("wheel_x",0x00)
    ]

class Logitech_Pairing_Request_Header(Packet):
    name = "Logitech Pairing Request Header"
    fields_desc = [
        ByteEnumField("pairing_phase", None, { 1 : "first_phase", 2 : "second_phase"}),
    ]

class Logitech_Pairing_Request_1_Payload(Packet):
    name = "Logitech Pairing Request 1 Payload"
    fields_desc = [
        SBAddressField("rf_address", None, length_from=lambda _ : 5),
        ByteField("unknown1", 0x08),
        ShortField("device_wpid", None),
        ByteEnumField("protocol_id", None, {0x04: "unifying"}),
        ByteField("unknown2", None),
        XShortEnumField("device_type", None, {0x020c: "mouse", 0x0147: "keyboard"}),
        ByteField("unknown3", None),
        StrFixedLenField("padding", b"\x00\x00\x00\x00\x00", length=5)
    ]

class Logitech_Pairing_Request_2_Payload(Packet):
    name = "Logitech Pairing Request 2 Payload"
    fields_desc = [
        StrFixedLenField("device_nonce", b"\x00\x00\x00\x00", length=4),
        StrFixedLenField("device_serial", b"\x00\x00\x00\x00", length=4),
        XShortEnumField("capabilities", None, {0x0400 : "mouse", 0x1e40: "keyboard"}),
        StrFixedLenField("unknown", b"\x00\x00\x00\x00\x00\x00\x00\x00", length=8),
    ]
class Logitech_Pairing_Request_3_Payload(Packet):
    name = "Logitech Pairing Request 3 Payload"
    fields_desc = [
        ByteField("type", None),
        FieldLenField("length", None, length_of="device_name", fmt="B"),
        StrLenField("device_name",None, length_from=lambda pkt:pkt.length),
        StrField("padding", None)

    ]

class Logitech_Pairing_Response_Header(Packet):
    name = "Logitech Pairing Response Header"
    fields_desc = [
        ByteEnumField("pairing_phase", None, { 1 : "first_phase", 2 : "second_phase", 3 : "final_phase"}),
    ]

class Logitech_Pairing_Response_1_Payload(Packet):
    name = "Logitech Pairing Response 1 Payload"
    fields_desc = [
        SBAddressField("rf_address", None, length_from=lambda _ : 5),
        ByteField("unknown1", 0x08),
        ShortField("dongle_wpid", None),
        ByteEnumField("protocol_id", None, {0x04: "unifying"}),
        ByteField("unknown2", None),
        ByteField("unknown3", None),
        ByteField("unknown4", None),
        StrFixedLenField("padding", b"\x00\x00\x00\x00\x00", length=6)
    ]


class Logitech_Pairing_Response_2_Payload(Packet):
    name = "Logitech Pairing Response 2 Payload"
    fields_desc = [
        StrFixedLenField("dongle_nonce", b"\x00\x00\x00\x00", length=4),
        StrFixedLenField("dongle_serial", b"\x00\x00\x00\x00", length=4),
        XShortEnumField("capabilities", None, {0x0400 : "mouse", 0x1e40: "keyboard"}),
        StrFixedLenField("unknown", b"\x00\x00\x00\x00\x00\x00\x00\x00", length=8),
    ]

class Logitech_Pairing_Confirm_Payload(Packet):
    name = "Logitech Pairing Confirm Payload"
    fields_desc = [
        StrFixedLenField("unknown", None, length=3),
        StrFixedLenField("nonce_fragment", None, length=2),
        StrFixedLenField("serial_fragment", None, length=2),
    ]

class Logitech_Pairing_Complete_Payload(Packet):
    name = "Logitech Pairing Complete Payload"
    fields_desc = [
        StrFixedLenField("padding", b"\x00\x00\x00\x00\x00\x00\x00", length=7)
    ]


class Logitech_Waked_Up_Payload(Packet):
    name = "Logitech Waked_Up Payload"
    fields_desc = [
        XByteField("wakeup_dev_index",None),
        StrFixedLenField("unknown3", b"\x00\x1F\x00\x00\x00\xFF", length=6),

    ]

def guess_payload_class_unifying(self, payload):
    if b"\x0f\x0f\x0f\x0f" == payload[:4]:
        return ESB_Ping_Request
    elif len(payload) == 0:
        return ESB_Ack_Response
    elif len(payload) >= 2 and payload[1] in (0x51,0xC2,0x40,0x4F,0xD3,0xC1,0xC3,0x5F,0x1F, 0x0F, 0x0E, 0x10):
        return Logitech_Unifying_Hdr
    else:
        return Packet.guess_payload_class(self, payload)


# Logitech Unifying protocol
bind_layers(Logitech_Unifying_Hdr, Logitech_Waked_Up_Payload,       frame_type = 0x10)
bind_layers(Logitech_Unifying_Hdr, Logitech_Wake_Up_Payload,                frame_type = 0x51)
bind_layers(Logitech_Unifying_Hdr, Logitech_Mouse_Payload,            frame_type = 0xC2)
bind_layers(Logitech_Unifying_Hdr, Logitech_Keepalive_Payload,             frame_type = 0x40)
bind_layers(Logitech_Unifying_Hdr, Logitech_Set_Keepalive_Payload,         frame_type = 0x4F)
bind_layers(Logitech_Unifying_Hdr, Logitech_Encrypted_Keystroke_Payload,     frame_type = 0xD3)
bind_layers(Logitech_Unifying_Hdr, Logitech_Unencrypted_Keystroke_Payload,     frame_type = 0xC1)
bind_layers(Logitech_Unifying_Hdr, Logitech_Multimedia_Key_Payload,         frame_type = 0xC3)
bind_layers(Logitech_Unifying_Hdr, Logitech_Pairing_Request_Header,         frame_type = 0x5F)
bind_layers( Logitech_Pairing_Request_Header,  Logitech_Pairing_Request_1_Payload,  pairing_phase = 0x01)
bind_layers( Logitech_Pairing_Request_Header,  Logitech_Pairing_Request_2_Payload,  pairing_phase = 0x02)
bind_layers( Logitech_Pairing_Request_Header,  Logitech_Pairing_Request_3_Payload,  pairing_phase = 0x03)

bind_layers(Logitech_Unifying_Hdr, Logitech_Pairing_Response_Header,         frame_type = 0x1F)
bind_layers(Logitech_Pairing_Response_Header,  Logitech_Pairing_Response_1_Payload,  pairing_phase = 0x01)
bind_layers(Logitech_Pairing_Response_Header,  Logitech_Pairing_Response_2_Payload,  pairing_phase = 0x02)

bind_layers(Logitech_Unifying_Hdr, Logitech_Pairing_Confirm_Payload,          frame_type = 0x0F)
bind_layers(Logitech_Unifying_Hdr, Logitech_Pairing_Complete_Payload,         frame_type = 0x0E)


def bind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_unifying

def unbind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_esb
