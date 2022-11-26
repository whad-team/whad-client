from scapy.packet import Packet, bind_layers
from scapy.fields import XByteEnumField, ByteField, LEShortField, ByteEnumField, \
    XByteField, BitField, BitEnumField, LESignedShortField, StrFixedLenField
from struct import pack
from whad.scapy.layers.esb import ESB_Payload_Hdr, SBAddressField, \
    guess_payload_class_esb

class Microsoft_Hdr(Packet):
    name = "Microsoft Header"
    fields_desc = [
        XByteEnumField("device_class",None, {0x0a: "keyboard", 0x08: "mouse"}),
        XByteEnumField("packet_type",  None, {0x78: "keystroke"}),
        XByteEnumField("model_id",None, {}),
        ByteField("unknown", 0x01),
        XByteField("checksum", None),
        ByteEnumField("valid_checksum", None, {0:"invalid", 1:"valid"}),
        LEShortField("sequence_number", None)
    ]

    @classmethod
    def compute_checksum(cls, data, key, init):
        checksum = init
        for i in data:
            checksum ^= i
        return checksum

    def pre_dissect(self, s):
        key = bytes.fromhex(self.underlayer.underlayer.address.replace(":",""))[::-1]

        unciphered = s[:4]

        count = 0
        deciphered = b""
        for i in s[4:-1]:
            deciphered += bytes([i ^ key[count]])
            count = (count + 1) % len(key)

        for i in range(len(key)):
            checksum = Microsoft_Hdr.compute_checksum(unciphered + deciphered, key, key[i] ^ 0xFF)
            if checksum == s[-1]:
                return unciphered + bytes([s[-1], int(True)]) + deciphered

        checksum = Microsoft_Hdr.compute_checksum(unciphered + s[4:-1], key, 0xFF)
        if checksum == s[-1]:
            return unciphered + bytes([s[-1], int(True)]) + s[4:-1]

        return unciphered + bytes([s[-1], int(False)]) + s[4:-1]

class Microsoft_Keystroke_Payload(Packet):
    name = "Microsoft Keystroke Payload"
    fields_desc = [
        ByteField("unknown2", 0x43),
        BitField("right_padding", 0, 1),
        BitEnumField("right_alt", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("right_shift", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("right_ctrl", 0, 1, {1:"pressed", 0:"released"}),
        BitField("left_padding", 0, 1),
        BitEnumField("left_alt", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("left_shift", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("left_ctrl", 0, 1, {1:"pressed", 0:"released"}),
        StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7),

    ]

class Microsoft_Mouse_Payload(Packet):
    name = "Microsoft Mouse Payload"
    fields_desc = [
        LEShortField("unknown2", 0x0040),
        BitField("padding", 0, 4),
        BitEnumField("special_click", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("middle_click", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("right_click", 0, 1, {1:"pressed", 0:"released"}),
        BitEnumField("left_click", 0, 1, {1:"pressed", 0:"released"}),
        LESignedShortField("x", None),
        LESignedShortField("y", None),
        LESignedShortField("wheel_y", None),
        LESignedShortField("wheel_x", None),
        ByteField("unknown3", 0x01),

    ]

def guess_payload_class_microsoft(self, payload):
    if b"\x0f\x0f\x0f\x0f" == payload[:4]:
        return ESB_Ping_Request
    elif len(payload) == 0:
        return ESB_Ack_Response
    elif len(payload) >= 2 and payload[0] in (0x08, 0x0a) and payload[1] in (0x78, 0x38, 0x90):
        return Microsoft_Hdr
    else:
        return Packet.guess_payload_class(self, payload)


# Microsoft protocol

bind_layers(Microsoft_Hdr, Microsoft_Keystroke_Payload, packet_type=0x78)
bind_layers(Microsoft_Hdr, Microsoft_Mouse_Payload, packet_type=0x90)

def bind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_microsoft

def unbind():
    ESB_Payload_Hdr.guess_payload_class = guess_payload_class_esb
