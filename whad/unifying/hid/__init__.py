from whad.unifying.hid.exceptions import InvalidHIDData
from whad.common.converters.hid import HIDConverter, HIDLocaleNotFound, HIDCodeNotFound
from whad.helpers import bytes_to_bits
from struct import pack

class LogitechUnifyingKeystrokeConverter(HIDConverter):
    @classmethod
    def get_key_from_hid_data(cls, hid_data, locale="fr"):

        if not isinstance(hid_data, bytes):
            raise InvalidHIDData(hid_data)

        if len(hid_data) != 7:
            raise InvalidHIDData(hid_data)

        modifiers = hid_data[0]
        hid_code = hid_data[1]
        return super().get_key_from_hid_code(hid_code, modifiers, locale=locale)

    @classmethod
    def get_hid_data_from_key(cls, key, ctrl=False, alt=False, shift=False, gui=False, locale="fr"):
        (hid_code, modifiers) = super().get_hid_code_from_key(key, ctrl=ctrl, alt=alt, shift=shift, gui=gui, locale=locale)

        hid_data = pack("B", modifiers) + pack("B", hid_code) + b"\x00"*5

        return hid_data

class LogitechUnifyingMouseMovementConverter:
    @classmethod
    def get_coordinates_from_hid_data(cls, hid_data):

        if not isinstance(hid_data, bytes):
            raise InvalidHIDData(hid_data)

        if len(hid_data) != 3:
            raise InvalidHIDData(hid_data)

        bits = bytes_to_bits(hid_data)
        xb = bits[12:16] + bits[0:8]
        yb =  bits[16:] + bits[8:12]

        if xb[0] == "0":
            x = sum([(2**(11-i))*int(xb[i]) for i in range(0,12)])
        else:
            x = -1*(1+sum([(2**(11-i))*(1 - int(xb[i])) for i in range(0,12)]))

        if yb[0] == "0":
            y = sum([(2**(11-i))*int(yb[i]) for i in range(0,12)])
        else:
            y = -1*(1+sum([(2**(11-i))*(1 - int(yb[i])) for i in range(0,12)]))

        return (x, y)

    @classmethod
    def get_hid_data_from_coordinates(cls, x, y):
        if (y < 0):
            y += 4096
        if (x < 0):
            x += 4096

        a,b,c = 0,0,0
        a = x & 0xFF

        b |= (x >> 8) & 0x0F
        c = (y >> 4) & 0xFF
        b |= (y << 4) & 0xF0

        ab = pack('B',a)
        bb = pack('B',b)
        cb = pack('B',c)

        return ab + bb + cb
