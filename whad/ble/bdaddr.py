import re
from binascii import hexlify, unhexlify
from whad.ble.exceptions import InvalidBDAddressException

class BDAddress(object):
    """This class represents a Bluetooth Device address
    """

    def __init__(self, address):
        """Initialize BD address
        """
        if isinstance(address, str):
            if re.match('^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = unhexlify(address.replace(':',''))[::-1]
            elif re.match('[0-9a-fA-F]{12}$', address) is not None:
                self.__value = unhexlify(address)[::-1]
            else:
                raise InvalidBDAddressException
        else:
            raise InvalidBDAddressException

    def __eq__(self, other):
        return self.__value == other.value

    def __str__(self):
        return ':'.join(['%02x' % b for b in self.__value[::-1]])

    def __repr__(self):
        return 'BDAddress(%s)' % str(self)

    @property
    def value(self):
        return self.__value

    @staticmethod
    def from_bytes(bd_addr_bytes):
        """Convert a 6-byte array into a valid BD address.

        :param bytes bd_addr_bytes: Bluetooth Device address as a bytearray.
        :rtype: BDAddress
        :returns: An instance of BDAddress representing the corresponding BD address.
        """
        if len(bd_addr_bytes) == 6:
            hex_address = hexlify(bd_addr_bytes[::-1])
            address = b':'.join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return BDAddress(address.decode('utf-8'))
        else:
            raise InvalidBDAddressException