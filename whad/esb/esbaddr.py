import re
from binascii import hexlify, unhexlify
from whad.esb.exceptions import InvalidESBAddressException

class ESBAddress(object):
    """This class represents an Enhanced ShockBurst address.
    """

    def __init__(self, address):
        """Initialize ESB address
        """
        if isinstance(address, str):
            if re.match(r'^([0-9a-fA-F]{2}\:){4}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = unhexlify(address.replace(':',''))
            elif re.match('[0-9a-fA-F]{10}$', address) is not None:
                self.__value = unhexlify(address)
            else:
                raise InvalidESBAddressException
        elif isinstance(address, bytes) and len(address) > 1 and len(address) <= 5:
            self.__value = address
        else:
            raise InvalidESBAddressException

    def __eq__(self, other):
        return (self.__value == other.value)

    def __str__(self):
        return ':'.join(['%02x' % b for b in self.__value])

    def __repr__(self):
        return 'ESBAddress(%s)' % str(self)

    @property
    def value(self):
        return self.__value

    @property
    def base(self):
        return ':'.join(['%02x' % b for b in self.__value[:4]])

    @property
    def prefix(self):
        return "{:02x}".format(self.__value[4])

    @staticmethod
    def from_bytes(esb_addr_bytes):
        """Convert a 5-byte array into a valid ESB address.

        :param bytes bd_addr_bytes: Enhanced ShockBurst address as a bytearray.
        :rtype: ESBAddress
        :returns: An instance of ESBAddress representing the corresponding ESB address.
        """
        if len(esb_addr_bytes) == 5:
            hex_address = hexlify(esb_addr_bytes)
            address = b':'.join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return ESBAddress(address.decode('utf-8'))
        else:
            raise InvalidESBAddressException
