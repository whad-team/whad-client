from whad.zigbee.stack.mac.helpers import is_short_address
from whad.zigbee.stack.mac.constants import MACAddressMode
from whad.zigbee.stack.apl.exceptions import APLInvalidAddress
from struct import unpack

class ZigbeeAddress:
    def __init__(self, address):
        self.broadcast = False
        if isinstance(address, int):
            if is_short_address(address):
                self.address = address
                if self.address in (0xFFFC,0xFFFD, 0xFFFE, 0xFFFF):
                    self.broadcast = True
                self.address_mode = MACAddressMode.SHORT
            else:
                self.address = address
                self.address_mode = MACAddressMode.EXTENDED

        elif isinstance(address, str):
            try:
                self.address = unpack("Q", bytes.fromhex(address.replace(":","")))[0]
                self.address_mode = MACAddressMode.EXTENDED
            except:
                raise APLInvalidAddress()
        else:
            raise APLInvalidAddress()

    def __repr__(self):
        if self.address_mode == MACAddressMode.SHORT:
            return "ZigbeeAddress(0x{:04x}, short)".format(self.address)
        else:
            return "ZigbeeAddress(0x{:016x}, extended)".format(self.address)

    def __eq__(self, other):
        return self.address == other.address and self.address_mode == other.adress_mode
